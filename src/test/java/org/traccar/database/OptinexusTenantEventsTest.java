package org.traccar.database;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.traccar.config.Config;
import org.traccar.helper.LogAction;
import org.traccar.model.Group;
import org.traccar.model.Permission;
import org.traccar.model.User;
import org.traccar.session.cache.CacheManager;
import org.traccar.storage.MemoryStorage;
import org.traccar.storage.Storage;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Request;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

public class OptinexusTenantEventsTest {

    private static final String TENANT = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";

    private Storage storage;
    private OpenIdTenantLinker linker;
    private OptinexusTenantEvents events;

    @BeforeEach
    public void setUp() {
        storage = new MemoryStorage();
        Config config = new Config();
        linker = new OpenIdTenantLinker(config, storage, mock(CacheManager.class), mock(LogAction.class));
        events = new OptinexusTenantEvents(config, linker);
    }

    private static String event(String type, String application, String tenant) {
        return "{\"event_id\":\"e1\",\"event_type\":\"" + type + "\",\"source_system\":\"optinexus\",\"tenant_id\":\""
                + tenant + "\",\"data\":{\"aggregate_type\":\"tenant\",\"payload\":{\"application_code\":\""
                + application + "\",\"tenant_name\":\"Acme Indonesia\"}}}";
    }

    private List<Group> groups() throws Exception {
        return storage.getObjects(Group.class, new Request(new Columns.All()));
    }

    @Test
    public void createsTheTenantGroupWhenOptiRadarIsAssigned() throws Exception {
        assertEquals(OptinexusTenantEvents.CREATED, events.handle(event(OptinexusTenantEvents.ASSIGNED, "optiradar", TENANT)));

        List<Group> groups = groups();
        assertEquals(1, groups.size());
        assertEquals("Acme Indonesia", groups.get(0).getName());
        assertEquals(TENANT, groups.get(0).getAttributes().get("optinexusTenantId"));
    }

    @Test
    public void doesNothingTheSecondTimeAndNeverAddsASecondGroup() throws Exception {
        events.handle(event(OptinexusTenantEvents.ASSIGNED, "optiradar", TENANT));
        assertEquals(OptinexusTenantEvents.EXISTS, events.handle(event(OptinexusTenantEvents.ASSIGNED, "optiradar", TENANT.toUpperCase())));
        assertEquals(1, groups().size());
    }

    @Test
    public void ignoresOtherApplicationsAndOtherEvents() throws Exception {
        assertEquals(OptinexusTenantEvents.IGNORED, events.handle(event(OptinexusTenantEvents.ASSIGNED, "optifleet", TENANT)));
        assertEquals(OptinexusTenantEvents.IGNORED, events.handle(event("cgo.tenant.application_removed", "optiradar", TENANT)));
        assertEquals(OptinexusTenantEvents.IGNORED, events.handle(event("optifleet.vehicle.status_changed", "optiradar", TENANT)));
        assertEquals(0, groups().size());
    }

    @Test
    public void refusesAnEventWithoutAValidTenant() {
        assertThrows(IllegalArgumentException.class, () -> events.handle(event(OptinexusTenantEvents.ASSIGNED, "optiradar", "")));
        assertThrows(IllegalArgumentException.class, () -> events.handle(event(OptinexusTenantEvents.ASSIGNED, "optiradar", "not-a-uuid")));
        assertThrows(IllegalArgumentException.class, () -> events.handle("[1]"));
    }

    private User addUser(String email, boolean administrator) throws Exception {
        User user = new User();
        user.setEmail(email);
        user.setAdministrator(administrator);
        user.setId(storage.addObject(user, new Request(new Columns.Exclude("id"))));
        return user;
    }

    private boolean linked(User user, Group group) throws Exception {
        return storage.getPermissions(User.class, user.getId(), Group.class, 0).stream()
                .anyMatch(permission -> permission.getPropertyId() == group.getId());
    }

    @Test
    public void linksTheNewGroupToEveryAdministratorSoTheyCanSeeIt() throws Exception {
        User admin = addUser("operator@example.test", true);
        User other = addUser("driver@example.test", false);

        events.handle(event(OptinexusTenantEvents.ASSIGNED, "optiradar", TENANT));

        Group group = groups().get(0);
        assertTrue(linked(admin, group));
        assertFalse(linked(other, group));
    }

    @Test
    public void anAdministratorLinkedToTenantGroupsBelongsToNoTenant() throws Exception {
        User admin = addUser("operator@example.test", true);
        User other = addUser("driver@example.test", false);
        events.handle(event(OptinexusTenantEvents.ASSIGNED, "optiradar", TENANT));
        storage.addPermission(new Permission(User.class, other.getId(), Group.class, groups().get(0).getId()));

        assertTrue(linker.tenantsOf(admin.getId()).isEmpty());
        assertEquals(java.util.Set.of(TENANT), linker.tenantsOf(other.getId()));
    }

    @Test
    public void usesTheTenantIdAsNameWhenTheEventHasNone() throws Exception {
        String body = event(OptinexusTenantEvents.ASSIGNED, "optiradar", TENANT).replace("Acme Indonesia", " ");
        events.handle(body);
        assertEquals(TENANT, groups().get(0).getName());
    }
}
