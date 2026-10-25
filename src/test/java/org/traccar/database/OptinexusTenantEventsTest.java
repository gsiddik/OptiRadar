package org.traccar.database;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.traccar.config.Config;
import org.traccar.helper.LogAction;
import org.traccar.model.Group;
import org.traccar.session.cache.CacheManager;
import org.traccar.storage.MemoryStorage;
import org.traccar.storage.Storage;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Request;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

public class OptinexusTenantEventsTest {

    private static final String TENANT = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";

    private Storage storage;
    private OptinexusTenantEvents events;

    @BeforeEach
    public void setUp() {
        storage = new MemoryStorage();
        Config config = new Config();
        OpenIdTenantLinker linker = new OpenIdTenantLinker(config, storage, mock(CacheManager.class), mock(LogAction.class));
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

    @Test
    public void usesTheTenantIdAsNameWhenTheEventHasNone() throws Exception {
        String body = event(OptinexusTenantEvents.ASSIGNED, "optiradar", TENANT).replace("Acme Indonesia", " ");
        events.handle(body);
        assertEquals(TENANT, groups().get(0).getName());
    }
}
