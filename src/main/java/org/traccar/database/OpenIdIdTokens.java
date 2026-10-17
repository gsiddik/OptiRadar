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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import java.net.URL;
import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Checks the ID token the provider returned for an authorization code (OIDC Core 3.1.3.7): the signature against the
 * provider's published keys (the key is picked by "kid"; an unknown "kid" makes the key set be fetched again, so a
 * rotation is followed), an allow-list of signature algorithms ("none" and symmetric algorithms never pass), issuer,
 * audience (and authorized party when there are several), expiry, issue time and the nonce of this very sign-in.
 */
public final class OpenIdIdTokens {

    private final IDTokenValidator validator;
    private final ClientID clientId;

    public OpenIdIdTokens(
            Issuer issuer, ClientID clientId, Set<JWSAlgorithm> algorithms, JWKSource<SecurityContext> keys) {
        this.clientId = clientId;
        validator = new IDTokenValidator(
                issuer, clientId, new JWSVerificationKeySelector<>(algorithms, keys), null);
    }

    public static OpenIdIdTokens create(
            Issuer issuer, ClientID clientId, Set<JWSAlgorithm> algorithms, URL jwkSetUrl) {
        return new OpenIdIdTokens(issuer, clientId, algorithms, JWKSourceBuilder.create(jwkSetUrl).build());
    }

    /**
     * The algorithms named in the configuration, RS256 when it is empty.
     *
     * @throws IllegalArgumentException for "none", a symmetric algorithm or a name that is not an algorithm
     */
    public static Set<JWSAlgorithm> parseAlgorithms(String value) {
        Set<JWSAlgorithm> result = new LinkedHashSet<>();
        for (String name : (value == null || value.isBlank() ? "RS256" : value).split(",")) {
            String trimmed = name.trim().toUpperCase(Locale.ROOT);
            if (trimmed.isEmpty()) {
                continue;
            }
            boolean asymmetric = trimmed.matches("(RS|PS|ES)(256|384|512)") || "EDDSA".equals(trimmed);
            if (!asymmetric) {
                throw new IllegalArgumentException("Unsupported ID token algorithm: " + name.trim());
            }
            result.add("EDDSA".equals(trimmed) ? JWSAlgorithm.EdDSA : JWSAlgorithm.parse(trimmed));
        }
        if (result.isEmpty()) {
            result.add(JWSAlgorithm.RS256);
        }
        return result;
    }

    /**
     * @return the subject of the verified token
     * @throws GeneralSecurityException if the token is not valid for this client and this sign-in
     */
    public String verify(String idToken, String expectedNonce) throws GeneralSecurityException {
        if (idToken == null || idToken.isBlank() || expectedNonce == null || expectedNonce.isBlank()) {
            throw new GeneralSecurityException("The OpenID provider returned no ID token");
        }
        try {
            JWT jwt = JWTParser.parse(idToken);
            IDTokenClaimsSet claims = validator.validate(jwt, new Nonce(expectedNonce));
            if (claims.getSubject() == null || claims.getSubject().getValue().isBlank()) {
                throw new GeneralSecurityException("The ID token has no subject");
            }
            if (claims.getAudience().size() > 1 && (claims.getAuthorizedParty() == null
                    || !clientId.getValue().equals(claims.getAuthorizedParty().getValue()))) {
                throw new GeneralSecurityException("Several audiences and no matching authorized party");
            }
            return claims.getSubject().getValue();
        } catch (ParseException | BadJOSEException | JOSEException e) {
            throw new GeneralSecurityException("Invalid ID token: " + e.getMessage(), e);
        }
    }

}
