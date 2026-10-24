package org.traccar.web;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class FrameAncestorsFilterTest {

    @Test
    public void allowsSelfAndTheConfiguredOrigins() {
        assertEquals("frame-ancestors 'self' https://deli.example.test https://*.example.org:8443",
                FrameAncestorsFilter.policy("https://deli.example.test https://*.example.org:8443"));
    }

    @Test
    public void dropsAnythingThatIsNotAPlainOrigin() {
        assertEquals("frame-ancestors 'self' https://ok.test",
                FrameAncestorsFilter.policy("* https://ok.test https://bad.test/path javascript:alert(1) https://x.test;script-src"));
    }

    @Test
    public void withoutOriginsOnlyTheServerItselfMayFrame() {
        assertEquals("frame-ancestors 'self'", FrameAncestorsFilter.policy(""));
        assertEquals("frame-ancestors 'self'", FrameAncestorsFilter.policy(null));
    }
}
