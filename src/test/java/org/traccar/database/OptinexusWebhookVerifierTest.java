package org.traccar.database;

import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OptinexusWebhookVerifierTest {

    private static final String SECRET = "whsec_test-secret";
    private static final String ID = "0c7a5c2e-8f0a-4a52-9a0e-4f1d6c0a1b11";
    private static final String BODY = "{\"event_type\":\"cgo.tenant.application_assigned\"}";
    private static final long NOW = 1_800_000_000L;

    private final OptinexusWebhookVerifier verifier = new OptinexusWebhookVerifier(SECRET);

    private String signature(long timestamp, String body) throws Exception {
        return "v1=" + OptinexusWebhookVerifier.sign(SECRET, ID, timestamp, body);
    }

    @Test
    public void acceptsAnUntouchedDeliveryInsideTheWindow() throws Exception {
        assertDoesNotThrow(() -> verifier.verify(ID, String.valueOf(NOW - 120), BODY, signature(NOW - 120, BODY), NOW));
        assertDoesNotThrow(() -> verifier.verify(ID, String.valueOf(NOW + 120), BODY, signature(NOW + 120, BODY), NOW));
    }

    @Test
    public void matchesTheSignatureOptiNexusProduces() throws Exception {
        // hash_hmac('sha256', "<id>.<timestamp>.<body>", secret) as computed by OptiNexus (WebhookSigner)
        assertTrue(OptinexusWebhookVerifier.sign(SECRET, ID, NOW, BODY).matches("[0-9a-f]{64}"));
    }

    @Test
    public void refusesATamperedBodyAnotherSecretOrAnotherDelivery() throws Exception {
        String good = signature(NOW, BODY);
        assertThrows(GeneralSecurityException.class,
                () -> verifier.verify(ID, String.valueOf(NOW), BODY + " ", good, NOW));
        assertThrows(GeneralSecurityException.class,
                () -> new OptinexusWebhookVerifier("whsec_other").verify(ID, String.valueOf(NOW), BODY, good, NOW));
        assertThrows(GeneralSecurityException.class,
                () -> verifier.verify("another-id", String.valueOf(NOW), BODY, good, NOW));
    }

    @Test
    public void refusesAStaleOrFutureTimestamp() throws Exception {
        long old = NOW - OptinexusWebhookVerifier.TOLERANCE_SECONDS - 1;
        assertThrows(GeneralSecurityException.class,
                () -> verifier.verify(ID, String.valueOf(old), BODY, signature(old, BODY), NOW));
        long future = NOW + OptinexusWebhookVerifier.TOLERANCE_SECONDS + 1;
        assertThrows(GeneralSecurityException.class,
                () -> verifier.verify(ID, String.valueOf(future), BODY, signature(future, BODY), NOW));
    }

    @Test
    public void refusesMissingOrMalformedParts() throws Exception {
        String good = signature(NOW, BODY);
        assertThrows(GeneralSecurityException.class, () -> verifier.verify(null, String.valueOf(NOW), BODY, good, NOW));
        assertThrows(GeneralSecurityException.class, () -> verifier.verify(ID, null, BODY, good, NOW));
        assertThrows(GeneralSecurityException.class, () -> verifier.verify(ID, "soon", BODY, good, NOW));
        assertThrows(GeneralSecurityException.class, () -> verifier.verify(ID, String.valueOf(NOW), BODY, null, NOW));
        assertThrows(GeneralSecurityException.class,
                () -> verifier.verify(ID, String.valueOf(NOW), BODY, good.substring(3), NOW));
    }

    @Test
    public void isOffWithoutASecretAndRefusesEverything() throws Exception {
        OptinexusWebhookVerifier off = new OptinexusWebhookVerifier("");
        assertFalse(off.enabled());
        assertThrows(GeneralSecurityException.class,
                () -> off.verify(ID, String.valueOf(NOW), BODY, signature(NOW, BODY), NOW));
        assertTrue(verifier.enabled());
    }
}
