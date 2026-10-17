package org.traccar.governance;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.traccar.api.security.ServiceAccountUser;
import org.traccar.config.Config;
import org.traccar.database.OpenIdApps;
import org.traccar.database.OpenIdLifecycle;
import org.traccar.model.BaseModel;
import org.traccar.model.Device;
import org.traccar.model.Geofence;
import org.traccar.model.Group;
import org.traccar.model.Notification;
import org.traccar.model.User;
import org.traccar.storage.MemoryStorage;
import org.traccar.storage.Storage;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Request;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class GovernanceGuardTest {

    private static final String TENANT_A = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";
    private static final String TENANT_B = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c02";

    private Storage storage;
    private GovernanceService governance;
    private GovernanceGuard guard;
    private User tenantUser;
    private User admin;

    @BeforeEach
    public void setUp() throws Exception {
        storage = new MemoryStorage();
        governance = mock(GovernanceService.class);
        when(governance.enabled()).thenReturn(true);
        guard = new GovernanceGuard(new Config(), storage, governance);
        tenantUser = add(new User());
        admin = new User();
        admin.setAdministrator(true);
        admin = add(admin);
        when(governance.principal(tenantUser.getId())).thenReturn(
                GovernedPrincipal.central(tenantUser.getId(), "5d3a7f9e-1b2c-4d5e-8f60-7a8b9c0d1e01", TENANT_A));
    }

    private <T extends BaseModel> T add(T entity) throws Exception {
        entity.setId(storage.addObject(entity, new Request(new Columns.Exclude("id"))));
        return entity;
    }

    @Test
    public void serviceAccountAndAdministratorsAreNotRestricted() throws Exception {
        Group group = new Group();
        group.set("optinexusTenantId", TENANT_B);

        assertDoesNotThrow(() -> guard.check(ServiceAccountUser.ID, group, true));
        assertDoesNotThrow(() -> guard.check(admin.getId(), group, true));
    }

    @Test
    public void otherObjectTypesAreNotTouched() throws Exception {
        Geofence geofence = new Geofence();

        assertDoesNotThrow(() -> guard.check(tenantUser.getId(), geofence, true));
        verify(governance, never()).principal(tenantUser.getId());
    }

    @Test
    public void tenantUserCannotSetTheTenantAttributeOfAGroup() throws Exception {
        Group group = new Group();
        group.setGroupId(1);
        group.set("optinexusTenantId", TENANT_B);

        GovernanceException e = assertThrows(GovernanceException.class,
                () -> guard.check(tenantUser.getId(), group, true));

        assertEquals(GovernanceException.RESERVED_ATTRIBUTE, e.getCode());
        assertEquals(403, e.getStatus());
    }

    @Test
    public void tenantUserCannotChangeOrRemoveTheTenantAttributeOfAStoredGroup() throws Exception {
        Group stored = new Group();
        stored.setName("Tenant A");
        stored.set("optinexusTenantId", TENANT_A);
        stored = add(stored);

        Group changed = new Group();
        changed.setId(stored.getId());
        changed.setGroupId(1);
        changed.set("optinexusTenantId", TENANT_B);
        Group removed = new Group();
        removed.setId(stored.getId());
        removed.setGroupId(1);
        Group same = new Group();
        same.setId(stored.getId());
        same.setGroupId(1);
        same.set("optinexusTenantId", TENANT_A);

        assertThrows(GovernanceException.class, () -> guard.check(tenantUser.getId(), changed, false));
        assertThrows(GovernanceException.class, () -> guard.check(tenantUser.getId(), removed, false));
        assertDoesNotThrow(() -> guard.check(tenantUser.getId(), same, false));
    }

    @Test
    public void tenantUserKeepsTheirPlainGroupsFreelyEditable() throws Exception {
        Group group = new Group();
        group.setName("Depot");
        group.setGroupId(1);

        assertDoesNotThrow(() -> guard.check(tenantUser.getId(), group, true));
    }

    @Test
    public void reservedUserAttributesAreRestoredFromTheStoredUser() throws Exception {
        User stored = new User();
        stored.setLogin("alice");
        stored.set(OpenIdLifecycle.SESSIONS_NOT_BEFORE, 1234L);
        stored.set(OpenIdLifecycle.DEACTIVATED, true);
        stored.getAttributes().put(OpenIdApps.ATTRIBUTE, List.of(Map.of("code", "optifleet")));
        stored = add(stored);

        User update = new User();
        update.setId(stored.getId());
        update.set(OpenIdLifecycle.SESSIONS_NOT_BEFORE, 0L);
        update.set(OpenIdLifecycle.LOGOUT_URL, "https://evil.example.test/");
        update.getAttributes().put(OpenIdApps.ATTRIBUTE, List.of(Map.of("code", "evil")));
        update.set("theme", "dark");

        guard.check(tenantUser.getId(), update, false);

        assertEquals(1234L, update.getLong(OpenIdLifecycle.SESSIONS_NOT_BEFORE));
        assertEquals(true, update.getAttributes().get(OpenIdLifecycle.DEACTIVATED));
        assertNull(update.getAttributes().get(OpenIdLifecycle.LOGOUT_URL), "a value the user never had is removed");
        assertEquals(List.of(Map.of("code", "optifleet")), update.getAttributes().get(OpenIdApps.ATTRIBUTE));
        assertEquals("dark", update.getAttributes().get("theme"), "ordinary attributes stay editable");
    }

    @Test
    public void devicesAndGroupsOfATenantUserMustSitBelowAGroup() throws Exception {
        Device device = new Device();
        device.setGroupId(0);
        Group group = new Group();
        group.setGroupId(0);

        assertEquals(GovernanceException.INVALID_PLACEMENT, assertThrows(GovernanceException.class,
                () -> guard.check(tenantUser.getId(), device, true)).getCode());
        assertEquals(400, assertThrows(GovernanceException.class,
                () -> guard.check(tenantUser.getId(), group, true)).getStatus());

        device.setGroupId(5);
        assertDoesNotThrow(() -> guard.check(tenantUser.getId(), device, true));
    }

    @Test
    public void placementIsNotEnforcedWhileGovernanceIsOff() throws Exception {
        when(governance.enabled()).thenReturn(false);
        Device device = new Device();

        assertDoesNotThrow(() -> guard.check(tenantUser.getId(), device, true));
    }

    @Test
    public void aNotificationThatSendsACommandNeedsThePermissionToSendCommands() throws Exception {
        Notification notification = new Notification();
        notification.setCommandId(4);
        doThrow(new GovernanceException(403, GovernanceException.PERMISSION_DENIED, "no", Catalog.COMMANDS_SEND))
                .when(governance).require(any(), anyCollection());

        GovernanceException e = assertThrows(GovernanceException.class,
                () -> guard.check(tenantUser.getId(), notification, true));

        assertEquals(Catalog.COMMANDS_SEND, e.getPermission());
        verify(governance).require(any(), eq(List.of(Catalog.COMMANDS_SEND)));
    }

    @Test
    public void theCommandNotificatorIsTreatedLikeACommand() throws Exception {
        Notification notification = new Notification();
        notification.setNotificators("web,command");

        guard.check(tenantUser.getId(), notification, true);

        verify(governance).require(any(), eq(List.of(Catalog.COMMANDS_SEND)));
    }

    @Test
    public void anOrdinaryNotificationNeedsNothingExtra() throws Exception {
        Notification notification = new Notification();
        notification.setNotificators("web,mail");

        guard.check(tenantUser.getId(), notification, true);

        verify(governance, never()).require(any(), anyCollection());
    }

}
