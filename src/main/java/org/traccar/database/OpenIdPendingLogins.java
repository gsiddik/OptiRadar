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

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Sign-ins that were started and not yet completed. Each one is created by this server when the browser is sent to
 * the provider, holds what only this server may know (nonce, PKCE verifier, redirect address) and is bound to the
 * browser that started it. It can be used once, for a short time: a callback with an unknown, repeated, expired or
 * foreign state is refused, and a state that was presented is gone whatever the outcome.
 */
public class OpenIdPendingLogins {

    public static final long DEFAULT_TTL_MILLIS = 10 * 60 * 1000;
    public static final int DEFAULT_CAPACITY = 5000;
    public static final int PER_BROWSER_LIMIT = 5;

    /**
     * @param state the one-time value sent to the provider and returned in the callback
     * @param nonce the value the ID token must carry
     * @param codeVerifier the PKCE verifier (its S256 challenge went to the provider)
     * @param redirectUri the redirect address used in the authorization request
     * @param browser the secret of the browser session that started the sign-in; null for the mobile app flow
     */
    public record Pending(
            String state, String nonce, String codeVerifier, String redirectUri, String browser, long createdAt) {
    }

    private final Clock clock;
    private final long ttlMillis;
    private final int capacity;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Pending> pending = new LinkedHashMap<>();

    public OpenIdPendingLogins() {
        this(Clock.systemUTC(), DEFAULT_TTL_MILLIS, DEFAULT_CAPACITY);
    }

    public OpenIdPendingLogins(Clock clock, long ttlMillis, int capacity) {
        this.clock = clock;
        this.ttlMillis = ttlMillis;
        this.capacity = capacity;
    }

    /**
     * A fresh random value for a browser secret.
     */
    public String newSecret() {
        return randomString();
    }

    /**
     * Starts a sign-in. The oldest pending sign-ins of the same browser, and the oldest overall when the store is
     * full, are dropped, so unauthenticated callers cannot make the server hold unbounded state.
     */
    public synchronized Pending start(String browser, String redirectUri, String codeVerifier) {
        long now = clock.millis();
        purge(now);
        Pending created = new Pending(randomString(), randomString(), codeVerifier, redirectUri, browser, now);

        if (browser != null) {
            long own = pending.values().stream().filter(item -> browser.equals(item.browser())).count();
            Iterator<Pending> iterator = pending.values().iterator();
            while (own >= PER_BROWSER_LIMIT && iterator.hasNext()) {
                if (browser.equals(iterator.next().browser())) {
                    iterator.remove();
                    own--;
                }
            }
        }
        Iterator<Pending> iterator = pending.values().iterator();
        while (pending.size() >= capacity && iterator.hasNext()) {
            iterator.next();
            iterator.remove();
        }

        pending.put(created.state(), created);
        return created;
    }

    /**
     * Takes the pending sign-in of a state out of the store.
     *
     * @param browser the secret of the browser that returned; must be the one that started a browser sign-in
     * @throws GeneralSecurityException if the state is unknown, used, expired, or belongs to another browser
     */
    public synchronized Pending consume(String state, String browser) throws GeneralSecurityException {
        long now = clock.millis();
        purge(now);
        if (state == null || state.isBlank()) {
            throw new GeneralSecurityException("Missing OpenID state");
        }
        Pending found = pending.remove(state);
        if (found == null) {
            throw new GeneralSecurityException("Unknown, expired or already used OpenID state");
        }
        if (found.browser() != null && !constantTimeEquals(found.browser(), browser)) {
            throw new GeneralSecurityException("The OpenID sign-in was not started in this browser");
        }
        return found;
    }

    public synchronized int size() {
        purge(clock.millis());
        return pending.size();
    }

    private void purge(long now) {
        pending.values().removeIf(item -> now - item.createdAt() > ttlMillis);
    }

    private String randomString() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        if (actual == null) {
            return false;
        }
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

}
