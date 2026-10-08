package org.traccar.database;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OpenIdAppsTest {

    @Test
    public void keepsNameAndAddressOfUsableApps() {
        var claim = List.of(
                Map.of("code", "optifleet", "name", "OptiFleet", "launch_url", "https://fleet.example.test/sso"),
                Map.of("code", "optiradar", "name", " OptiRadar ", "launch_url", "http://radar.example.test/"));

        assertEquals(List.of(
                Map.of("name", "OptiFleet", "url", "https://fleet.example.test/sso"),
                Map.of("name", "OptiRadar", "url", "http://radar.example.test/")), OpenIdApps.parse(claim));
    }

    @Test
    public void dropsEntriesThatCannotBeLinkedSafely() {
        var claim = List.of(
                Map.of("name", "Script", "launch_url", "javascript:alert(1)"),
                Map.of("name", "File", "launch_url", "file:///etc/passwd"),
                Map.of("name", "No host", "launch_url", "https:///path"),
                Map.of("name", "Garbage", "launch_url", "not a url"),
                Map.of("name", "", "launch_url", "https://blank.example.test/"),
                Map.of("name", "No address"),
                "not an object");

        assertTrue(OpenIdApps.parse(claim).isEmpty());
    }

    @Test
    public void toleratesMissingOrWrongClaims() {
        assertTrue(OpenIdApps.parse(null).isEmpty());
        assertTrue(OpenIdApps.parse("optifleet").isEmpty());
        assertTrue(OpenIdApps.parse(Map.of("name", "x")).isEmpty());
    }
}
