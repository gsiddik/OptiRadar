package org.traccar.database;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class OpenIdIdTokensTest {

    private static final String ISSUER = "https://nexus.example.test";
    private static final String CLIENT = "radar-client";
    private static final String NONCE = "nonce-of-this-sign-in";

    private RSAKey key;
    private final AtomicReference<JWKSet> published = new AtomicReference<>();
    private OpenIdIdTokens tokens;

    @BeforeEach
    public void setUp() throws Exception {
        key = new RSAKeyGenerator(2048).keyID("key-1").generate();
        published.set(new JWKSet(key.toPublicJWK()));
        JWKSource<SecurityContext> source = (selector, context) -> selector.select(published.get());
        tokens = new OpenIdIdTokens(new Issuer(ISSUER), new ClientID(CLIENT), Set.of(JWSAlgorithm.RS256), source);
    }

    private JWTClaimsSet.Builder claims() {
        long now = System.currentTimeMillis();
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("user-1")
                .audience(CLIENT)
                .issueTime(new Date(now))
                .expirationTime(new Date(now + 300_000))
                .claim("nonce", NONCE);
    }

    private String sign(RSAKey signingKey, JWTClaimsSet claims) throws Exception {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).type(JOSEObjectType.JWT).build(),
                claims);
        jwt.sign(new RSASSASigner(signingKey));
        return jwt.serialize();
    }

    private String sign(Consumer<JWTClaimsSet.Builder> change) throws Exception {
        JWTClaimsSet.Builder builder = claims();
        change.accept(builder);
        return sign(key, builder.build());
    }

    @Test
    public void acceptsAValidTokenAndReturnsItsSubject() throws Exception {
        assertEquals("user-1", tokens.verify(sign(builder -> { }), NONCE));
    }

    @Test
    public void refusesAnotherNonceOrNoNonceAtAll() throws Exception {
        assertThrows(GeneralSecurityException.class, () -> tokens.verify(sign(builder -> { }), "someone-elses-nonce"));
        assertThrows(GeneralSecurityException.class, () -> tokens.verify(sign(builder -> builder.claim("nonce", null)), NONCE));
        assertThrows(GeneralSecurityException.class, () -> tokens.verify(sign(builder -> { }), null));
    }

    @Test
    public void refusesAWrongIssuerAudienceOrAuthorizedParty() throws Exception {
        assertThrows(GeneralSecurityException.class,
                () -> tokens.verify(sign(builder -> builder.issuer("https://evil.example.test")), NONCE));
        assertThrows(GeneralSecurityException.class,
                () -> tokens.verify(sign(builder -> builder.audience("another-client")), NONCE));
        assertThrows(GeneralSecurityException.class,
                () -> tokens.verify(sign(builder -> builder.audience(List.of(CLIENT, "other"))), NONCE),
                "several audiences need an authorized party");
        assertThrows(GeneralSecurityException.class,
                () -> tokens.verify(sign(builder -> builder.audience(List.of(CLIENT, "other")).claim("azp", "other")), NONCE));
        assertEquals("user-1", tokens.verify(
                sign(builder -> builder.audience(List.of(CLIENT, "other")).claim("azp", CLIENT)), NONCE));
    }

    @Test
    public void refusesExpiredAndNotYetIssuedTokens() throws Exception {
        long now = System.currentTimeMillis();
        assertThrows(GeneralSecurityException.class, () -> tokens.verify(
                sign(builder -> builder.issueTime(new Date(now - 7_200_000)).expirationTime(new Date(now - 3_600_000))),
                NONCE));
        assertThrows(GeneralSecurityException.class, () -> tokens.verify(
                sign(builder -> builder.issueTime(new Date(now + 3_600_000)).expirationTime(new Date(now + 7_200_000))),
                NONCE));
    }

    @Test
    public void refusesATokenWithoutSubject() throws Exception {
        assertThrows(GeneralSecurityException.class, () -> tokens.verify(sign(builder -> builder.subject(null)), NONCE));
    }

    @Test
    public void refusesATokenSignedWithAnotherKeyEvenWithTheSameKeyId() throws Exception {
        RSAKey attacker = new RSAKeyGenerator(2048).keyID("key-1").generate();

        assertThrows(GeneralSecurityException.class,
                () -> tokens.verify(sign(attacker, claims().build()), NONCE));
    }

    @Test
    public void refusesTamperedPayloads() throws Exception {
        String token = sign(builder -> { });
        String[] parts = token.split("\\.");
        String forged = new String(java.util.Base64.getUrlDecoder().decode(parts[1]), java.nio.charset.StandardCharsets.UTF_8)
                .replace("user-1", "admin-1");
        String tampered = parts[0] + "." + java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(forged.getBytes(java.nio.charset.StandardCharsets.UTF_8)) + "." + parts[2];

        assertThrows(GeneralSecurityException.class, () -> tokens.verify(tampered, NONCE));
    }

    @Test
    public void refusesUnsignedTokensAndAlgorithmConfusion() throws Exception {
        String unsigned = new PlainJWT(claims().build()).serialize();
        assertThrows(GeneralSecurityException.class, () -> tokens.verify(unsigned, NONCE));

        // HS256 signed with the public key material as the shared secret (the classic confusion attack).
        SignedJWT hmac = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("key-1").build(), claims().build());
        hmac.sign(new MACSigner(new byte[32]));
        assertThrows(GeneralSecurityException.class, () -> tokens.verify(hmac.serialize(), NONCE));

        // RS256 is not on the allow-list of this validator when only ES256 is configured.
        OpenIdIdTokens onlyEs = new OpenIdIdTokens(new Issuer(ISSUER), new ClientID(CLIENT),
                Set.of(JWSAlgorithm.ES256), new ImmutableJWKSet<>(published.get()));
        assertThrows(GeneralSecurityException.class, () -> onlyEs.verify(sign(builder -> { }), NONCE));
    }

    @Test
    public void refusesGarbageAndMissingTokens() {
        assertThrows(GeneralSecurityException.class, () -> tokens.verify("not-a-jwt", NONCE));
        assertThrows(GeneralSecurityException.class, () -> tokens.verify("", NONCE));
        assertThrows(GeneralSecurityException.class, () -> tokens.verify(null, NONCE));
    }

    @Test
    public void followsAKeyRotationAndStopsTrustingARetiredKey() throws Exception {
        RSAKey rotated = new RSAKeyGenerator(2048).keyID("key-2").generate();
        String signedWithNew = sign(rotated, claims().build());

        assertThrows(GeneralSecurityException.class, () -> tokens.verify(signedWithNew, NONCE), "not published yet");

        published.set(new JWKSet(List.of(rotated.toPublicJWK(), key.toPublicJWK())));
        assertEquals("user-1", tokens.verify(signedWithNew, NONCE), "published");
        assertEquals("user-1", tokens.verify(sign(builder -> { }), NONCE), "the old key is still published");

        published.set(new JWKSet(rotated.toPublicJWK()));
        assertThrows(GeneralSecurityException.class, () -> tokens.verify(sign(builder -> { }), NONCE), "retired");
    }

    @Test
    public void onlyAsymmetricAlgorithmsCanBeConfigured() {
        assertEquals(Set.of(JWSAlgorithm.RS256), OpenIdIdTokens.parseAlgorithms(null));
        assertEquals(Set.of(JWSAlgorithm.RS256, JWSAlgorithm.ES256), OpenIdIdTokens.parseAlgorithms("rs256, ES256"));
        assertThrows(IllegalArgumentException.class, () -> OpenIdIdTokens.parseAlgorithms("none"));
        assertThrows(IllegalArgumentException.class, () -> OpenIdIdTokens.parseAlgorithms("HS256"));
        assertThrows(IllegalArgumentException.class, () -> OpenIdIdTokens.parseAlgorithms("RS256,bogus"));
    }

}
