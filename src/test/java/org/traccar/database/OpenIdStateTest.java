package org.traccar.database;

import org.junit.jupiter.api.Test;

import jakarta.servlet.http.HttpSession;
import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class OpenIdStateTest {

    private HttpSession sessionWith(String state) {
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute(OpenIdState.ATTRIBUTE)).thenReturn(state);
        return session;
    }

    @Test
    public void acceptsTheStateThatWasSentAndForgetsIt() {
        HttpSession session = sessionWith("abc");
        assertDoesNotThrow(() -> OpenIdState.verify(session, "abc"));
        verify(session).removeAttribute(OpenIdState.ATTRIBUTE);
    }

    @Test
    public void handsBackTheRememberedCodeVerifierOnlyOnce() {
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute(OpenIdState.VERIFIER_ATTRIBUTE)).thenReturn("verifier-value");
        org.junit.jupiter.api.Assertions.assertEquals("verifier-value", OpenIdState.takeVerifier(session));
        verify(session).removeAttribute(OpenIdState.VERIFIER_ATTRIBUTE);
    }

    @Test
    public void hasNoCodeVerifierWithoutASessionOrWhenNoneWasRemembered() {
        org.junit.jupiter.api.Assertions.assertNull(OpenIdState.takeVerifier(null));
        org.junit.jupiter.api.Assertions.assertNull(OpenIdState.takeVerifier(mock(HttpSession.class)));
    }

    @Test
    public void refusesAnotherMissingOrUnknownState() {
        assertThrows(GeneralSecurityException.class, () -> OpenIdState.verify(sessionWith("abc"), "xyz"));
        assertThrows(GeneralSecurityException.class, () -> OpenIdState.verify(sessionWith("abc"), null));
        assertThrows(GeneralSecurityException.class, () -> OpenIdState.verify(sessionWith("abc"), ""));
        assertThrows(GeneralSecurityException.class, () -> OpenIdState.verify(sessionWith(null), "abc"));
        assertThrows(GeneralSecurityException.class, () -> OpenIdState.verify(null, "abc"));
    }
}
