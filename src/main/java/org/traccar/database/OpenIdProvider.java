/*
 * Copyright 2025 - 2026 Anton Tananaev (anton@traccar.org)
 * Copyright 2023 Daniel Raper (me@danr.uk)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.database;

import com.google.inject.Inject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.traccar.api.security.LoginService;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.helper.LogAction;
import org.traccar.helper.SessionHelper;
import org.traccar.helper.WebHelper;
import org.traccar.model.Group;
import org.traccar.model.User;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * OpenID Connect authorization-code sign-in with a confidential client.
 *
 * <p>Every sign-in is started here: the server creates a one-time state, a nonce and a PKCE (S256) verifier, keeps them
 * (see {@link OpenIdPendingLogins}) bound to the browser that started it, and only accepts a callback that returns that
 * state in the same browser within a few minutes. The ID token returned for the code is verified completely (see
 * {@link OpenIdIdTokens}) and its subject must be the subject the user info endpoint reports. The account is the one
 * linked to the provider's identity (issuer + subject, see {@link OpenIdIdentities}), not the one with the same
 * email.</p>
 */
public class OpenIdProvider {

    static final String BROWSER_KEY = "openidBrowser";
    private static final String MOBILE_SCHEME = "org.traccar.manager";

    /**
     * What the provider publishes (or the configuration states when there is no discovery).
     */
    record Metadata(
            Issuer issuer, URI authUrl, URI tokenUrl, URI userInfoUrl, URI endSessionUrl,
            OpenIdIdTokens idTokens, OpenIdLogoutTokens logoutTokens) {
    }

    private final Boolean force;
    private final ClientID clientId;
    private final ClientAuthentication clientAuth;
    private final URI callbackUrl;
    private final URI baseUrl;
    private final Metadata metadata;
    private final boolean allowMobileRedirect;
    private final String adminGroup;
    private final String allowGroup;
    private final String groupsClaimName;
    private final String tenantClaim;

    private final LoginService loginService;
    private final OpenIdTenantLinker tenantLinker;
    private final OpenIdLifecycle lifecycle;
    private final LogAction actionLogger;
    private final OpenIdPendingLogins pendingLogins;

    @Inject
    public OpenIdProvider(
            Config config, LoginService loginService, LogAction actionLogger, OpenIdTenantLinker tenantLinker,
            OpenIdLifecycle lifecycle)
            throws IOException, URISyntaxException, GeneralException {
        this(config, loginService, actionLogger, tenantLinker, lifecycle, resolveMetadata(config),
                new OpenIdPendingLogins());
    }

    OpenIdProvider(
            Config config, LoginService loginService, LogAction actionLogger, OpenIdTenantLinker tenantLinker,
            OpenIdLifecycle lifecycle, Metadata metadata, OpenIdPendingLogins pendingLogins) {

        this.loginService = loginService;
        this.tenantLinker = tenantLinker;
        this.lifecycle = lifecycle;
        this.actionLogger = actionLogger;
        this.metadata = metadata;
        this.pendingLogins = pendingLogins;

        force = config.getBoolean(Keys.OPENID_FORCE);
        clientId = new ClientID(config.getString(Keys.OPENID_CLIENT_ID));
        clientAuth = new ClientSecretBasic(clientId, new Secret(config.getString(Keys.OPENID_CLIENT_SECRET)));

        baseUrl = URI.create(WebHelper.retrieveWebUrl(config));
        callbackUrl = URI.create(WebHelper.retrieveWebUrl(config) + "/api/session/openid/callback");
        allowMobileRedirect = config.getBoolean(Keys.OPENID_ALLOW_MOBILE_REDIRECT);

        adminGroup = config.getString(Keys.OPENID_ADMIN_GROUP);
        allowGroup = config.getString(Keys.OPENID_ALLOW_GROUP);
        groupsClaimName = config.getString(Keys.OPENID_GROUPS_CLAIM_NAME);
        tenantClaim = config.getString(Keys.OPENID_TENANT_CLAIM);
    }

    private static Metadata resolveMetadata(Config config)
            throws IOException, URISyntaxException, GeneralException {

        ClientID clientId = new ClientID(config.getString(Keys.OPENID_CLIENT_ID));
        Set<JWSAlgorithm> algorithms = OpenIdIdTokens.parseAlgorithms(
                config.getString(Keys.OPENID_ID_TOKEN_ALGORITHMS));

        if (config.hasKey(Keys.OPENID_ISSUER_URL)) {
            OIDCProviderMetadata meta = OIDCProviderMetadata.resolve(
                    new Issuer(config.getString(Keys.OPENID_ISSUER_URL)));
            if (meta.getJWKSetURI() == null) {
                throw new IllegalStateException("The OpenID provider publishes no key set (jwks_uri)");
            }
            URL keys = meta.getJWKSetURI().toURL();
            return new Metadata(
                    meta.getIssuer(),
                    meta.getAuthorizationEndpointURI(), meta.getTokenEndpointURI(), meta.getUserInfoEndpointURI(),
                    meta.getEndSessionEndpointURI(),
                    OpenIdIdTokens.create(meta.getIssuer(), clientId, algorithms, keys),
                    // Back-channel logout needs the provider's key set, which only discovery gives us.
                    OpenIdLogoutTokens.create(meta.getIssuer(), clientId, keys));
        }

        // Without discovery the issuer and the key set must be stated: an ID token is never accepted unverified.
        if (!config.hasKey(Keys.OPENID_ISSUER) || !config.hasKey(Keys.OPENID_JWKS_URL)) {
            throw new IllegalStateException(
                    "openid.issuer and openid.jwksUrl are required when openid.issuerUrl is not set");
        }
        Issuer issuer = new Issuer(config.getString(Keys.OPENID_ISSUER));
        return new Metadata(
                issuer,
                new URI(config.getString(Keys.OPENID_AUTH_URL)),
                new URI(config.getString(Keys.OPENID_TOKEN_URL)),
                new URI(config.getString(Keys.OPENID_USERINFO_URL)),
                null,
                OpenIdIdTokens.create(issuer, clientId, algorithms, new URL(config.getString(Keys.OPENID_JWKS_URL))),
                null);
    }

    /**
     * Starts a sign-in from the browser: creates the one-time state, nonce and PKCE verifier, and returns the
     * authorization request to send the browser to.
     *
     * @param mobileRedirect redirect address of the mobile app, only honored when openid.allowMobileRedirect is set
     */
    public URI createAuthUri(HttpServletRequest request, String mobileRedirect) throws GeneralSecurityException {
        String redirectUri = callbackUrl.toString();
        String browser = null;
        if (mobileRedirect != null) {
            if (!allowMobileRedirect || !MOBILE_SCHEME.equals(URI.create(mobileRedirect).getScheme())) {
                throw new GeneralSecurityException("Invalid redirect URI");
            }
            redirectUri = mobileRedirect;
        } else {
            HttpSession session = request.getSession(true);
            browser = (String) session.getAttribute(BROWSER_KEY);
            if (browser == null) {
                browser = pendingLogins.newSecret();
                session.setAttribute(BROWSER_KEY, browser);
            }
        }

        CodeVerifier verifier = new CodeVerifier();
        OpenIdPendingLogins.Pending pending = pendingLogins.start(browser, redirectUri, verifier.getValue());

        Scope scope = new Scope("openid", "profile", "email");
        if (adminGroup != null) {
            scope.add(groupsClaimName);
        }
        return new AuthenticationRequest.Builder(new ResponseType("code"), scope, clientId, URI.create(redirectUri))
                .endpointURI(metadata.authUrl())
                .state(new State(pending.state()))
                .nonce(new Nonce(pending.nonce()))
                .codeChallenge(verifier, CodeChallengeMethod.S256)
                .build()
                .toURI();
    }

    protected OIDCTokenResponse getToken(
            URI redirectUri, AuthorizationCode code, CodeVerifier verifier)
            throws IOException, ParseException, GeneralSecurityException {

        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, redirectUri, verifier);
        TokenRequest tokenRequest = new TokenRequest(metadata.tokenUrl(), clientAuth, codeGrant, null);

        HTTPResponse tokenResponse = tokenRequest.toHTTPRequest().send();
        TokenResponse token = OIDCTokenResponseParser.parse(tokenResponse);
        if (!token.indicatesSuccess()) {
            throw new GeneralSecurityException("Unable to authenticate with the OpenID Connect provider");
        }

        return (OIDCTokenResponse) token.toSuccessResponse();
    }

    protected UserInfo getUserInfo(
            BearerAccessToken token) throws IOException, ParseException, GeneralSecurityException {

        HTTPResponse httpResponse = new UserInfoRequest(metadata.userInfoUrl(), token)
                .toHTTPRequest()
                .send();

        UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponse);

        if (!userInfoResponse.indicatesSuccess()) {
            throw new GeneralSecurityException("Failed to access OpenID Connect user info endpoint");
        }

        return userInfoResponse.toSuccessResponse().getUserInfo();
    }

    public URI handleCallback(String queryParameters, HttpServletRequest request)
            throws Exception {

        Map<String, List<String>> parameters = URLUtils.parseParameters(queryParameters);

        // The state is looked up first and is used up whatever happens next: a callback can only ever be tried once.
        HttpSession session = request.getSession(false);
        String browser = session != null ? (String) session.getAttribute(BROWSER_KEY) : null;
        OpenIdPendingLogins.Pending pending = pendingLogins.consume(first(parameters, "state"), browser);
        URI redirectUri = URI.create(pending.redirectUri());

        String redirectOverride = request.getParameter("redirect_uri");
        if (redirectOverride != null && !redirectOverride.equals(pending.redirectUri())) {
            throw new GeneralSecurityException("Invalid redirect URI");
        }
        String issuerParameter = first(parameters, "iss");
        if (issuerParameter != null && !issuerParameter.equals(metadata.issuer().getValue())) {
            throw new GeneralSecurityException("Unexpected OpenID issuer");
        }

        AuthorizationResponse response = AuthorizationResponse.parse(redirectUri, parameters);

        if (!response.indicatesSuccess()) {
            throw new GeneralSecurityException(response.toErrorResponse().getErrorObject().getDescription());
        }

        AuthorizationCode authCode = response.toSuccessResponse().getAuthorizationCode();
        if (authCode == null) {
            throw new GeneralSecurityException("Malformed OpenID callback");
        }

        OIDCTokenResponse tokens = getToken(redirectUri, authCode, new CodeVerifier(pending.codeVerifier()));

        String subject = metadata.idTokens().verify(tokens.getOIDCTokens().getIDTokenString(), pending.nonce());

        BearerAccessToken bearerToken = tokens.getOIDCTokens().getBearerAccessToken();

        UserInfo userInfo = getUserInfo(bearerToken);
        if (userInfo.getSubject() == null || !subject.equals(userInfo.getSubject().getValue())) {
            throw new GeneralSecurityException("The user info does not belong to the ID token subject");
        }

        List<String> userGroups = userInfo.getStringListClaim(groupsClaimName);
        Boolean administrator = adminGroup != null && userGroups != null ? userGroups.contains(adminGroup) : null;

        if (!(Boolean.TRUE.equals(administrator) || allowGroup == null
                || (userGroups != null && userGroups.contains(allowGroup)))) {
            throw new GeneralSecurityException("Your OpenID Groups do not permit access");
        }

        Group tenantGroup = null;
        if (tenantClaim != null) {
            // The tenant decides which devices the user can see, so it is resolved (and the email trusted)
            // before an account is created or changed.
            if (!Boolean.TRUE.equals(userInfo.getEmailVerified())) {
                throw new GeneralSecurityException("Your email address is not verified");
            }
            tenantGroup = tenantLinker.findGroup(userInfo.getStringClaim(tenantClaim));
        }

        OpenIdIdentities.Claims claims = new OpenIdIdentities.Claims(
                metadata.issuer().getValue(), subject, userInfo.getEmailAddress(),
                Boolean.TRUE.equals(userInfo.getEmailVerified()));
        User user = loginService.login(request, claims, userInfo.getName(), administrator).getUser();

        if (tenantGroup != null) {
            if (tenantLinker.link(request, user, tenantGroup)) {
                // One tenant is active per account: sessions opened before this sign-in end, so none of them
                // silently gets the scope of the tenant just chosen.
                lifecycle.endSessions(user);
            }
            tenantLinker.rememberApps(user, OpenIdApps.parse(userInfo.getClaim("apps")));
            lifecycle.rememberLogoutUrl(user, logoutUrl());
        }

        SessionHelper.userLogin(actionLogger, request, user, null);

        return baseUrl.resolve("?openid=success");
    }

    /**
     * Where the browser is sent when a sign-in is refused; the web app shows a generic message.
     */
    public URI failureUri() {
        return baseUrl.resolve("?openid=error");
    }

    private static String first(Map<String, List<String>> parameters, String name) {
        List<String> values = parameters.get(name);
        return values == null || values.isEmpty() ? null : values.get(0);
    }

    /**
     * Where the web app sends the browser after it ended the local session, so the provider signs the user out of
     * every application. Null when the provider does not publish an end session endpoint.
     */
    public String logoutUrl() {
        URI endSessionUrl = metadata.endSessionUrl();
        if (endSessionUrl == null) {
            return null;
        }
        String separator = endSessionUrl.getQuery() == null ? "?" : "&";
        return endSessionUrl + separator + "client_id=" + URLEncoder.encode(clientId.getValue(), StandardCharsets.UTF_8)
                + "&post_logout_redirect_uri=" + URLEncoder.encode(baseUrl.toString(), StandardCharsets.UTF_8);
    }

    /**
     * Handles a logout token pushed by the provider (OIDC Back-Channel Logout).
     *
     * @throws GeneralSecurityException if the token is not valid, or the provider is not set up for the feature
     */
    public void handleBackchannelLogout(String logoutToken) throws Exception {
        if (metadata.logoutTokens() == null) {
            throw new GeneralSecurityException("Back-channel logout needs openid.issuerUrl");
        }
        lifecycle.apply(metadata.logoutTokens().verify(logoutToken));
    }

    public boolean getForce() {
        return force;
    }
}
