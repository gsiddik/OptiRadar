package org.traccar.config;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ConfigTest {

    @Test
    public void testFormat() {
        assertEquals("DATABASE_URL", Config.getEnvironmentVariableName("database.url"));
        assertEquals("DATABASE_CHECK_CONNECTION", Config.getEnvironmentVariableName("database.checkConnection"));
        assertEquals("DATABASE_MAX_POOL_SIZE", Config.getEnvironmentVariableName("database.maxPoolSize"));
        assertEquals("DEVICE_MANAGER_LOOKUP_GROUPS_ATTRIBUTE", Config.getEnvironmentVariableName("deviceManager.lookupGroupsAttribute"));
        assertEquals("COMMAND_FALLBACK_TO_SMS", Config.getEnvironmentVariableName("command.fallbackToSms"));
        assertEquals("STATUS_TIMEOUT", Config.getEnvironmentVariableName("status.timeout"));
    }

    @Test
    public void testEmptyEnvironmentValueIsNotSet() {
        assertTrue(Config.hasEnvironmentValue(Map.of("WEB_FRAME_ANCESTORS", "http://deli.localtest.me:5200"), "web.frameAncestors"));
        assertFalse(Config.hasEnvironmentValue(Map.of("WEB_FRAME_ANCESTORS", ""), "web.frameAncestors"));
        assertFalse(Config.hasEnvironmentValue(Map.of("OPENID_CLIENT_ID", ""), "openid.clientId"));
        assertFalse(Config.hasEnvironmentValue(Map.of(), "openid.clientId"));
    }

}
