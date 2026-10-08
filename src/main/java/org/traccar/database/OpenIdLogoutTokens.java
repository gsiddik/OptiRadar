/*
 * Copyright 2026 Anton Tananaev (anton@traccar.org)
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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.claims.LogoutTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.LogoutTokenValidator;

import java.net.URL;
import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Checks the logout tokens an OpenID provider pushes to the back-channel logout endpoint (OIDC Back-Channel Logout
 * 1.0): signature against the provider's key set, issuer, audience, freshness, the logout event, a subject and no
 * nonce, and refuses a token id it has already seen. The provider's custom access-revoked event, when present, is
 * reported next to it.
 */
public final class OpenIdLogoutTokens {

    public static final String LOGOUT_TOKEN_TYPE = "logout+jwt";
    public static final String ACCESS_REVOKED_EVENT = "https://schemas.optinexus.io/event/access-revoked";

    private static final long REMEMBER_MILLIS = 15 * 60 * 1000;

    /**
     * What the provider said about the user.
     *
     * @param subject the provider's id of the user
     * @param email the user's email, if the provider sent it
     * @param accessRevoked true when the user must also be deactivated, not only logged out
     * @param tenantScope true when only one tenant is affected
     * @param tenantId the affected tenant, with tenantScope
     */
    public record Event(String subject, String email, boolean accessRevoked, boolean tenantScope, String tenantId) {
    }

    private final LogoutTokenValidator validator;
    private final Map<String, Long> seen = new ConcurrentHashMap<>();

    public OpenIdLogoutTokens(LogoutTokenValidator validator) {
        this.validator = validator;
    }

    public static OpenIdLogoutTokens create(Issuer issuer, ClientID clientId, URL jwkSetUrl) {
        return new OpenIdLogoutTokens(new LogoutTokenValidator(issuer, clientId, JWSAlgorithm.RS256, jwkSetUrl));
    }

    public static OpenIdLogoutTokens create(Issuer issuer, ClientID clientId, JWKSet keys) {
        return new OpenIdLogoutTokens(new LogoutTokenValidator(issuer, clientId, JWSAlgorithm.RS256, keys));
    }

    public Event verify(String token) throws GeneralSecurityException {
        if (token == null || token.isBlank()) {
            throw new GeneralSecurityException("Missing logout token");
        }

        LogoutTokenClaimsSet claims;
        JWTClaimsSet all;
        try {
            JWT jwt = JWTParser.parse(token);
            requireLogoutType(jwt);
            claims = validator.validate(jwt);
            all = jwt.getJWTClaimsSet();
        } catch (ParseException | BadJOSEException | JOSEException e) {
            throw new GeneralSecurityException("Invalid logout token: " + e.getMessage(), e);
        }

        rememberOrReject(claims.getJWTID().getValue());

        String email;
        Object custom;
        try {
            email = all.getStringClaim("email");
            Object events = all.getClaim(LogoutTokenClaimsSet.EVENTS_CLAIM_NAME);
            custom = events instanceof Map<?, ?> map ? map.get(ACCESS_REVOKED_EVENT) : null;
        } catch (ParseException e) {
            throw new GeneralSecurityException("Invalid logout token: " + e.getMessage(), e);
        }

        boolean tenantScope = false;
        String tenantId = null;
        if (custom instanceof Map<?, ?> details) {
            tenantScope = "tenant".equals(details.get("scope"));
            tenantId = details.get("tenant_id") instanceof String value ? value : null;
        }

        return new Event(
                claims.getSubject() != null ? claims.getSubject().getValue() : null,
                email, custom != null, tenantScope, tenantId);
    }

    /**
     * A token that is explicitly typed as something else (an id_token is "JWT") is not a logout token. Tokens
     * without a type are still accepted, as the specification only recommends the explicit type.
     */
    private void requireLogoutType(JWT jwt) throws GeneralSecurityException {
        JOSEObjectType type = jwt.getHeader().getType();
        if (type != null && !LOGOUT_TOKEN_TYPE.equalsIgnoreCase(type.getType())) {
            throw new GeneralSecurityException("Not a logout token (typ " + type.getType() + ")");
        }
    }

    private void rememberOrReject(String id) throws GeneralSecurityException {
        long now = System.currentTimeMillis();
        seen.values().removeIf(at -> now - at > REMEMBER_MILLIS);
        if (seen.putIfAbsent(id, now) != null) {
            throw new GeneralSecurityException("Logout token already used");
        }
    }

}
