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

import org.traccar.config.Config;
import org.traccar.config.Keys;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Checks the signature of an OptiNexus event broker webhook:
 * {@code Opti-Webhook-Signature: v1=<hex HMAC-SHA256(secret, "<id>.<timestamp>.<body>")>}. A delivery older (or newer)
 * than five minutes is refused so a captured request cannot be replayed later. The secret is the one issued with the
 * event subscription of OptiRadar; without it the endpoint is switched off.
 */
@Singleton
public class OptinexusWebhookVerifier {

    static final long TOLERANCE_SECONDS = 300;

    private static final String PREFIX = "v1=";

    private final String secret;

    @Inject
    public OptinexusWebhookVerifier(Config config) {
        this(config.getString(Keys.OPTINEXUS_WEBHOOK_SECRET));
    }

    OptinexusWebhookVerifier(String secret) {
        this.secret = secret;
    }

    public boolean enabled() {
        return secret != null && !secret.isEmpty();
    }

    public void verify(
            String deliveryId, String timestamp, String body, String signature) throws GeneralSecurityException {
        verify(deliveryId, timestamp, body, signature, System.currentTimeMillis() / 1000);
    }

    void verify(String deliveryId, String timestamp, String body, String signature, long nowSeconds)
            throws GeneralSecurityException {
        if (!enabled()) {
            throw new GeneralSecurityException("The OptiNexus webhook is not configured");
        }
        if (deliveryId == null || deliveryId.isEmpty() || timestamp == null || body == null
                || signature == null || !signature.startsWith(PREFIX)) {
            throw new GeneralSecurityException("The webhook signature is missing");
        }
        long sent;
        try {
            sent = Long.parseLong(timestamp.trim());
        } catch (NumberFormatException e) {
            throw new GeneralSecurityException("The webhook timestamp is not valid");
        }
        if (Math.abs(nowSeconds - sent) > TOLERANCE_SECONDS) {
            throw new GeneralSecurityException("The webhook timestamp is outside the accepted window");
        }
        byte[] expected = sign(secret, deliveryId, sent, body).getBytes(StandardCharsets.US_ASCII);
        byte[] given = signature.substring(PREFIX.length()).trim().getBytes(StandardCharsets.US_ASCII);
        if (!MessageDigest.isEqual(expected, given)) {
            throw new GeneralSecurityException("The webhook signature does not match");
        }
    }

    static String sign(String secret, String deliveryId, long timestamp, String body)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] digest = mac.doFinal((deliveryId + "." + timestamp + "." + body).getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder(digest.length * 2);
        for (byte value : digest) {
            hex.append(String.format("%02x", value));
        }
        return hex.toString();
    }

}
