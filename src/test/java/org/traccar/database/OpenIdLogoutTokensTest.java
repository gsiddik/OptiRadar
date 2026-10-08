package org.traccar.database;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OpenIdLogoutTokensTest {

    private static final String ISSUER = "https://nexus.example.test";
    private static final String CLIENT = "onx_radar";
    private static final String LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";
    private static final String TENANT = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";

    private RSAKey key;
    private OpenIdLogoutTokens tokens;

    @BeforeEach
    public void setUp() throws Exception {
        key = new RSAKeyGenerator(2048).keyID("k1").generate();
        tokens = OpenIdLogoutTokens.create(new Issuer(ISSUER), new ClientID(CLIENT), new JWKSet(key.toPublicJWK()));
    }

    private String sign(RSAKey signingKey, String type, Consumer<JWTClaimsSet.Builder> customize) throws Exception {
        Map<String, Object> events = new LinkedHashMap<>();
        events.put(LOGOUT_EVENT, Map.of());
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(CLIENT)
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 120_000))
                .jwtID(UUID.randomUUID().toString())
                .subject("user-1")
                .claim("email", "driver@example.test")
                .claim("events", events);
        customize.accept(claims);
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).type(new JOSEObjectType(type))
                        .build(),
                claims.build());
        jwt.sign(new RSASSASigner(signingKey));
        return jwt.serialize();
    }

    private String sign(Consumer<JWTClaimsSet.Builder> customize) throws Exception {
        return sign(key, "logout+jwt", customize);
    }

    private static Map<String, Object> eventsWith(Map<String, Object> accessRevoked) {
        Map<String, Object> events = new LinkedHashMap<>();
        events.put(LOGOUT_EVENT, Map.of());
        if (accessRevoked != null) {
            events.put(OpenIdLogoutTokens.ACCESS_REVOKED_EVENT, accessRevoked);
        }
        return events;
    }

    @Test
    public void acceptsAPlainLogout() throws Exception {
        OpenIdLogoutTokens.Event event = tokens.verify(sign(claims -> { }));

        assertEquals("user-1", event.subject());
        assertEquals("driver@example.test", event.email());
        assertFalse(event.accessRevoked());
        assertFalse(event.tenantScope());
        assertNull(event.tenantId());
    }

    @Test
    public void readsTheAccessRevokedEventForTheWholeUser() throws Exception {
        OpenIdLogoutTokens.Event event = tokens.verify(sign(claims -> claims.claim("events",
                eventsWith(Map.of("reason", "user_suspended", "scope", "user")))));

        assertTrue(event.accessRevoked());
        assertFalse(event.tenantScope());
    }

    @Test
    public void readsTheAccessRevokedEventForOneTenant() throws Exception {
        OpenIdLogoutTokens.Event event = tokens.verify(sign(claims -> claims.claim("events",
                eventsWith(Map.of("reason", "tenant_membership_removed", "scope", "tenant", "tenant_id", TENANT)))));

        assertTrue(event.accessRevoked());
        assertTrue(event.tenantScope());
        assertEquals(TENANT, event.tenantId());
    }

    @Test
    public void refusesATokenItHasAlreadySeen() throws Exception {
        String token = sign(claims -> { });

        tokens.verify(token);

        assertThrows(GeneralSecurityException.class, () -> tokens.verify(token));
    }

    @Test
    public void refusesBlankAndMalformedTokens() {
        assertThrows(GeneralSecurityException.class, () -> tokens.verify(null));
        assertThrows(GeneralSecurityException.class, () -> tokens.verify(" "));
        assertThrows(GeneralSecurityException.class, () -> tokens.verify("not.a.jwt"));
    }

    @Test
    public void refusesATokenSignedByAnotherKey() throws Exception {
        RSAKey stranger = new RSAKeyGenerator(2048).keyID("k1").generate();

        assertThrows(GeneralSecurityException.class, () -> tokens.verify(sign(stranger, "logout+jwt", claims -> { })));
    }

    @Test
    public void refusesTheWrongIssuerAudienceOrAge() throws Exception {
        assertThrows(GeneralSecurityException.class,
                () -> tokens.verify(sign(claims -> claims.issuer("https://evil.example.test"))));
        assertThrows(GeneralSecurityException.class, () -> tokens.verify(sign(claims -> claims.audience("other"))));
        assertThrows(GeneralSecurityException.class, () -> tokens.verify(sign(claims -> claims
                .issueTime(new Date(System.currentTimeMillis() - 3_600_000))
                .expirationTime(new Date(System.currentTimeMillis() - 3_000_000)))));
    }

    @Test
    public void refusesATokenWithoutTheLogoutEventASubjectOrWithANonce() throws Exception {
        assertThrows(GeneralSecurityException.class,
                () -> tokens.verify(sign(claims -> claims.claim("events", Map.of("other", Map.of())))));
        assertThrows(GeneralSecurityException.class, () -> tokens.verify(sign(claims -> claims.subject(null))));
        assertThrows(GeneralSecurityException.class, () -> tokens.verify(sign(claims -> claims.claim("nonce", "abc"))));
    }

    @Test
    public void anIdTokenCannotPassForALogoutToken() throws Exception {
        // Same key, same issuer and audience, but typed as an id_token and without the logout event.
        String idToken = sign(key, "JWT", claims -> claims.claim("events", null).claim("nonce", "n"));

        assertThrows(GeneralSecurityException.class, () -> tokens.verify(idToken));
    }

    @Test
    public void refusesATokenTypedAsAnIdToken() throws Exception {
        assertThrows(GeneralSecurityException.class, () -> tokens.verify(sign(key, "JWT", claims -> { })));
    }

}
