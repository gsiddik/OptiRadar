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

import jakarta.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/**
 * The OpenID Connect {@code state}: a value sent with the authorization request that must come back unchanged on the
 * callback in the same browser session, so a callback that this browser did not start is refused (login CSRF).
 */
public final class OpenIdState {

    static final String ATTRIBUTE = "openid.state";

    private OpenIdState() {
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    /** Remembers the state of an authorization request in the session. */
    public static void remember(HttpSession session, String state) {
        session.setAttribute(ATTRIBUTE, state);
    }

    /**
     * Checks the state of a callback against the one remembered, once: the remembered value is removed whatever the
     * outcome.
     *
     * @throws GeneralSecurityException if there is none remembered, none returned, or they differ
     */
    public static void verify(HttpSession session, String returned) throws GeneralSecurityException {
        Object expected = session != null ? session.getAttribute(ATTRIBUTE) : null;
        if (session != null) {
            session.removeAttribute(ATTRIBUTE);
        }
        if (!(expected instanceof String) || returned == null || returned.isEmpty()
                || !MessageDigest.isEqual(bytes((String) expected), bytes(returned))) {
            throw new GeneralSecurityException("The OpenID login was not started from this browser");
        }
    }

}
