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
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
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
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.List;

public class OpenIdProvider {
    private final Boolean force;
    private final ClientID clientId;
    private final ClientAuthentication clientAuth;
    private final URI callbackUrl;
    private final URI authUrl;
    private final URI tokenUrl;
    private final URI userInfoUrl;
    private final URI baseUrl;
    private final String adminGroup;
    private final String allowGroup;
    private final String groupsClaimName;
    private final String tenantClaim;
    private final URI endSessionUrl;
    private final OpenIdLogoutTokens logoutTokens;

    private final LoginService loginService;
    private final OpenIdTenantLinker tenantLinker;
    private final OpenIdLifecycle lifecycle;
    private final LogAction actionLogger;

    @Inject
    public OpenIdProvider(
            Config config, LoginService loginService, LogAction actionLogger, OpenIdTenantLinker tenantLinker,
            OpenIdLifecycle lifecycle)
            throws IOException, URISyntaxException, GeneralException {

        this.loginService = loginService;
        this.tenantLinker = tenantLinker;
        this.lifecycle = lifecycle;
        this.actionLogger = actionLogger;

        force = config.getBoolean(Keys.OPENID_FORCE);
        clientId = new ClientID(config.getString(Keys.OPENID_CLIENT_ID));
        clientAuth = new ClientSecretBasic(clientId, new Secret(config.getString(Keys.OPENID_CLIENT_SECRET)));

        baseUrl = URI.create(WebHelper.retrieveWebUrl(config));
        callbackUrl = URI.create(WebHelper.retrieveWebUrl(config) + "/api/session/openid/callback");

        if (config.hasKey(Keys.OPENID_ISSUER_URL)) {
            OIDCProviderMetadata meta = OIDCProviderMetadata.resolve(
                    new Issuer(config.getString(Keys.OPENID_ISSUER_URL)));
            authUrl = meta.getAuthorizationEndpointURI();
            tokenUrl = meta.getTokenEndpointURI();
            userInfoUrl = meta.getUserInfoEndpointURI();
            endSessionUrl = meta.getEndSessionEndpointURI();
            // Back-channel logout needs the provider's key set, which only discovery gives us.
            logoutTokens = meta.getJWKSetURI() != null
                    ? OpenIdLogoutTokens.create(meta.getIssuer(), clientId, meta.getJWKSetURI().toURL()) : null;
        } else {
            authUrl = new URI(config.getString(Keys.OPENID_AUTH_URL));
            tokenUrl = new URI(config.getString(Keys.OPENID_TOKEN_URL));
            userInfoUrl = new URI(config.getString(Keys.OPENID_USERINFO_URL));
            endSessionUrl = null;
            logoutTokens = null;
        }

        adminGroup = config.getString(Keys.OPENID_ADMIN_GROUP);
        allowGroup = config.getString(Keys.OPENID_ALLOW_GROUP);
        groupsClaimName = config.getString(Keys.OPENID_GROUPS_CLAIM_NAME);
        tenantClaim = config.getString(Keys.OPENID_TENANT_CLAIM);
    }

    public URI createAuthUri() {
        Scope scope = new Scope("openid", "profile", "email");
        if (adminGroup != null) {
            scope.add(groupsClaimName);
        }
        return new AuthenticationRequest.Builder(new ResponseType("code"), scope, clientId, callbackUrl)
                .endpointURI(authUrl)
                .state(new State())
                .build()
                .toURI();
    }

    private OIDCTokenResponse getToken(
            URI redirectUri, AuthorizationCode code) throws IOException, ParseException, GeneralSecurityException {

        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, redirectUri);
        TokenRequest tokenRequest = new TokenRequest(tokenUrl, clientAuth, codeGrant, null);

        HTTPResponse tokenResponse = tokenRequest.toHTTPRequest().send();
        TokenResponse token = OIDCTokenResponseParser.parse(tokenResponse);
        if (!token.indicatesSuccess()) {
            throw new GeneralSecurityException("Unable to authenticate with the OpenID Connect provider");
        }

        return (OIDCTokenResponse) token.toSuccessResponse();
    }

    private UserInfo getUserInfo(
            BearerAccessToken token) throws IOException, ParseException, GeneralSecurityException {

        HTTPResponse httpResponse = new UserInfoRequest(userInfoUrl, token)
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

        String redirectUriOverride = request.getParameter("redirect_uri");
        URI redirectUri;
        if (redirectUriOverride != null) {
            redirectUri = URI.create(redirectUriOverride);
            if (!"org.traccar.manager".equals(redirectUri.getScheme())) {
                throw new GeneralSecurityException("Invalid redirect URI");
            }
        } else {
            redirectUri = callbackUrl;
        }
        AuthorizationResponse response = AuthorizationResponse.parse(
                redirectUri, URLUtils.parseParameters(queryParameters));

        if (!response.indicatesSuccess()) {
            throw new GeneralSecurityException(response.toErrorResponse().getErrorObject().getDescription());
        }

        AuthorizationCode authCode = response.toSuccessResponse().getAuthorizationCode();
        if (authCode == null) {
            throw new GeneralSecurityException("Malformed OpenID callback");
        }

        OIDCTokenResponse tokens = getToken(redirectUri, authCode);

        BearerAccessToken bearerToken = tokens.getOIDCTokens().getBearerAccessToken();

        UserInfo userInfo = getUserInfo(bearerToken);

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

        User user = loginService.login(
                userInfo.getEmailAddress(), userInfo.getName(), administrator).getUser();

        if (tenantGroup != null) {
            tenantLinker.link(request, user, tenantGroup);
            tenantLinker.rememberApps(user, OpenIdApps.parse(userInfo.getClaim("apps")));
            lifecycle.rememberLogoutUrl(user, logoutUrl());
        }

        SessionHelper.userLogin(actionLogger, request, user, null);

        return baseUrl.resolve("?openid=success");
    }

    /**
     * Where the web app sends the browser after it ended the local session, so the provider signs the user out of
     * every application. Null when the provider does not publish an end session endpoint.
     */
    public String logoutUrl() {
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
        if (logoutTokens == null) {
            throw new GeneralSecurityException("Back-channel logout needs openid.issuerUrl");
        }
        lifecycle.apply(logoutTokens.verify(logoutToken));
    }

    public boolean getForce() {
        return force;
    }
}
