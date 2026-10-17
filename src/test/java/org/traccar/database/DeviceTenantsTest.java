package org.traccar.database;

import org.junit.jupiter.api.Test;
import org.traccar.model.Device;
import org.traccar.model.Group;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class DeviceTenantsTest {

    private static final String ATTRIBUTE = "optinexusTenantId";
    private static final String TENANT = "0B1F6C1E-6A3A-4C5E-9D52-6F0F6A1B2C01";

    private final Map<Long, Group> groups = new HashMap<>();

    private Group group(long id, long parent, String tenant) {
        Group group = new Group();
        group.setId(id);
        group.setGroupId(parent);
        if (tenant != null) {
            group.set(ATTRIBUTE, tenant);
        }
        groups.put(id, group);
        return group;
    }

    private Device device(long groupId) {
        Device device = new Device();
        device.setGroupId(groupId);
        return device;
    }

    @Test
    public void theNearestGroupThatNamesATenantWinsAndTheIdIsLowerCase() {
        group(1, 0, TENANT);
        group(2, 1, null);
        group(3, 2, "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c02");

        assertEquals(TENANT.toLowerCase(), DeviceTenants.tenantOf(device(2), groups::get, ATTRIBUTE));
        assertEquals("0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c02", DeviceTenants.tenantOf(device(3), groups::get, ATTRIBUTE));
    }

    @Test
    public void noGroupNoTenantNoSuchGroupNoTenantAndATextThatIsNotAnIdIsNoTenant() {
        group(1, 0, null);
        group(2, 0, "acme");

        assertNull(DeviceTenants.tenantOf(device(0), groups::get, ATTRIBUTE));
        assertNull(DeviceTenants.tenantOf(device(1), groups::get, ATTRIBUTE));
        assertNull(DeviceTenants.tenantOf(device(99), groups::get, ATTRIBUTE));
        assertNull(DeviceTenants.tenantOf(device(2), groups::get, ATTRIBUTE));
    }

    @Test
    public void aLoopOfGroupsEndsInsteadOfSpinning() {
        group(1, 2, null);
        group(2, 1, null);

        assertNull(DeviceTenants.tenantOf(device(1), groups::get, ATTRIBUTE));
    }

    @Test
    public void aTenantTooFarUpIsNotFound() {
        group(1, 0, TENANT);
        for (long id = 2; id <= 15; id++) {
            group(id, id - 1, null);
        }

        assertNull(DeviceTenants.tenantOf(device(15), groups::get, ATTRIBUTE));
        assertEquals(TENANT.toLowerCase(), DeviceTenants.tenantOf(device(5), groups::get, ATTRIBUTE));
    }

}
