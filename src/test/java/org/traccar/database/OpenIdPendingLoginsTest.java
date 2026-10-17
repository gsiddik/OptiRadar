package org.traccar.database;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.ThrowingSupplier;

import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OpenIdPendingLoginsTest {

    private static final String REDIRECT = "https://radar.example.test/api/session/openid/callback";

    private long now;
    private OpenIdPendingLogins logins;

    private final Clock clock = new Clock() {
        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochMilli(now);
        }
    };

    @BeforeEach
    public void setUp() {
        now = 1_000_000;
        logins = new OpenIdPendingLogins(clock, 10 * 60 * 1000, 100);
    }

    @Test
    public void everySignInGetsItsOwnUnpredictableStateAndNonce() {
        Set<String> values = new HashSet<>();
        for (int i = 0; i < 50; i++) {
            OpenIdPendingLogins.Pending pending = logins.start("browser-1", REDIRECT, "verifier");
            assertTrue(pending.state().length() >= 43, "256 bits of randomness");
            assertTrue(values.add(pending.state()));
            assertTrue(values.add(pending.nonce()));
            assertNotEquals(pending.state(), pending.nonce());
        }
    }

    @Test
    public void aStateWorksOnceInTheBrowserThatStartedItAndKeepsWhatOnlyTheServerKnows() throws Exception {
        OpenIdPendingLogins.Pending started = logins.start("browser-1", REDIRECT, "verifier-1");

        OpenIdPendingLogins.Pending taken = logins.consume(started.state(), "browser-1");

        assertEquals(started.nonce(), taken.nonce());
        assertEquals("verifier-1", taken.codeVerifier());
        assertEquals(REDIRECT, taken.redirectUri());
        assertThrows(GeneralSecurityException.class, () -> logins.consume(started.state(), "browser-1"), "replay");
    }

    @Test
    public void aStateReturnedInAnotherBrowserIsRefusedAndStaysUsedUp() {
        OpenIdPendingLogins.Pending started = logins.start("browser-1", REDIRECT, "verifier");

        assertThrows(GeneralSecurityException.class, () -> logins.consume(started.state(), "browser-2"));
        assertThrows(GeneralSecurityException.class, () -> logins.consume(started.state(), null));
        assertThrows(GeneralSecurityException.class, () -> logins.consume(started.state(), "browser-1"),
                "the legitimate browser cannot reuse a state that was already presented");
    }

    @Test
    public void unknownBlankAndMissingStatesAreRefused() {
        logins.start("browser-1", REDIRECT, "verifier");

        assertThrows(GeneralSecurityException.class, () -> logins.consume("made-up", "browser-1"));
        assertThrows(GeneralSecurityException.class, () -> logins.consume("", "browser-1"));
        assertThrows(GeneralSecurityException.class, () -> logins.consume(null, "browser-1"));
    }

    @Test
    public void aStateExpiresAfterTheTimeToLive() throws Exception {
        OpenIdPendingLogins.Pending fresh = logins.start("browser-1", REDIRECT, "verifier");
        OpenIdPendingLogins.Pending stale = logins.start("browser-1", REDIRECT, "verifier");

        now += 10 * 60 * 1000;
        assertEquals(fresh.nonce(), logins.consume(fresh.state(), "browser-1").nonce(), "exactly at the limit");

        now += 1;
        assertThrows(GeneralSecurityException.class, () -> logins.consume(stale.state(), "browser-1"));
        assertEquals(0, logins.size());
    }

    @Test
    public void aBrowserCannotHoldMoreThanAFewSignInsAndTheOldestGoFirst() {
        OpenIdPendingLogins.Pending oldest = logins.start("browser-1", REDIRECT, "verifier");
        for (int i = 0; i < OpenIdPendingLogins.PER_BROWSER_LIMIT; i++) {
            logins.start("browser-1", REDIRECT, "verifier");
        }
        OpenIdPendingLogins.Pending other = logins.start("browser-2", REDIRECT, "verifier");

        assertThrows(GeneralSecurityException.class, () -> logins.consume(oldest.state(), "browser-1"));
        assertEquals(OpenIdPendingLogins.PER_BROWSER_LIMIT + 1, logins.size());
        assertEquals(other.nonce(), assertDoesNotThrow(() -> logins.consume(other.state(), "browser-2")).nonce());
    }

    @Test
    public void theStoreIsBoundedSoUnauthenticatedCallersCannotFillTheMemory() {
        OpenIdPendingLogins small = new OpenIdPendingLogins(clock, 10 * 60 * 1000, 10);
        for (int i = 0; i < 1000; i++) {
            small.start("browser-" + i, REDIRECT, "verifier");
        }
        assertEquals(10, small.size());
    }

    @Test
    public void aMobileSignInHasNoBrowserBindingButIsStillOneTime() throws Exception {
        OpenIdPendingLogins.Pending started = logins.start(null, "org.traccar.manager://openid", "verifier");

        assertEquals("org.traccar.manager://openid", logins.consume(started.state(), null).redirectUri());
        assertThrows(GeneralSecurityException.class, () -> logins.consume(started.state(), null));
    }

    private static <T> T assertDoesNotThrow(ThrowingSupplier<T> supplier) {
        return org.junit.jupiter.api.Assertions.assertDoesNotThrow(supplier);
    }

}
