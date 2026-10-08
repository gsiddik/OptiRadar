package org.traccar.database;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.model.Device;
import org.traccar.model.Event;
import org.traccar.model.Geofence;
import org.traccar.model.Group;
import org.traccar.model.OptinexusOutboxEvent;
import org.traccar.model.Position;
import org.traccar.session.cache.CacheManager;
import org.traccar.storage.MemoryStorage;
import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Request;

import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OptinexusEventRecorderTest {

    private static final String TENANT_A = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";
    private static final String ATTRIBUTE = "optinexusTenantId";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<Long, Device> devices = new HashMap<>();
    private final Map<Long, Group> groups = new HashMap<>();
    private final Map<Long, Geofence> geofences = new HashMap<>();

    private Storage storage;
    private CacheManager cacheManager;
    private OptinexusEventRecorder recorder;

    @BeforeEach
    public void setUp() {
        storage = new MemoryStorage();
        cacheManager = mock(CacheManager.class);
        when(cacheManager.getObject(any(), anyLong())).thenAnswer(invocation -> {
            Class<?> type = invocation.getArgument(0);
            long id = invocation.getArgument(1);
            if (type == Device.class) {
                return devices.get(id);
            } else if (type == Group.class) {
                return groups.get(id);
            } else if (type == Geofence.class) {
                return geofences.get(id);
            }
            return null;
        });
        recorder = newRecorder(true, storage);
    }

    private OptinexusEventRecorder newRecorder(boolean enabled, Storage useStorage) {
        Config config = new Config();
        config.setString(Keys.OPTINEXUS_EVENTS_ENABLE, String.valueOf(enabled));
        return new OptinexusEventRecorder(config, useStorage, cacheManager, objectMapper);
    }

    private Group addGroup(long id, Long parentId, String tenantId) {
        Group group = new Group();
        group.setId(id);
        group.setName("Group " + id);
        if (parentId != null) {
            group.setGroupId(parentId);
        }
        if (tenantId != null) {
            group.set(ATTRIBUTE, tenantId);
        }
        groups.put(id, group);
        return group;
    }

    private Device addDevice(long id, long groupId) {
        Device device = new Device();
        device.setId(id);
        device.setName("Truck " + id);
        device.setUniqueId("IMEI" + id);
        device.setGroupId(groupId);
        devices.put(id, device);
        return device;
    }

    private Position position(long deviceId, double speedKnots) {
        Position position = new Position();
        position.setId(77);
        position.setDeviceId(deviceId);
        position.setLatitude(-6.2);
        position.setLongitude(106.8);
        position.setSpeed(speedKnots);
        position.setFixTime(new Date(1_700_000_000_000L));
        return position;
    }

    private List<OptinexusOutboxEvent> rows() throws StorageException {
        return storage.getObjects(OptinexusOutboxEvent.class, new Request(new Columns.All())).stream()
                .sorted(Comparator.comparingLong(OptinexusOutboxEvent::getId))
                .toList();
    }

    private JsonNode data(OptinexusOutboxEvent row) throws Exception {
        return objectMapper.readTree(row.getPayload());
    }

    @Test
    public void recordsAnOverspeedEventOfATenantDeviceWithItsSpeedInKilometresPerHour() throws Exception {
        addGroup(1, null, TENANT_A);
        addDevice(10, 1);
        Event event = new Event(Event.TYPE_DEVICE_OVERSPEED, 10);
        event.setId(5);
        event.set("speed", 54.0);
        event.set(Position.KEY_SPEED_LIMIT, 27.0);

        recorder.record(event, position(10, 54.0));

        OptinexusOutboxEvent row = rows().get(0);
        assertEquals("optiradar.device.overspeed", row.getEventKey());
        assertEquals(TENANT_A, row.getTenantId());
        assertEquals(10, row.getDeviceId());
        assertEquals(5, row.getSourceEventId());
        assertEquals(OptinexusOutboxEvent.STATUS_PENDING, row.getStatus());
        assertEquals(0, row.getAttempts());
        assertEquals(event.getEventTime(), row.getOccurredAt());
        UUID.fromString(row.getEventUuid());

        JsonNode data = data(row);
        assertEquals("device", data.get("aggregate_type").asText());
        assertEquals("10", data.get("aggregate_id").asText());
        assertEquals("IMEI10", data.get("correlation").get("unique_id").asText());
        JsonNode payload = data.get("payload");
        assertEquals(100.0, payload.get("speed_kmh").asDouble(), 0.01);
        assertEquals(50.0, payload.get("speed_limit_kmh").asDouble(), 0.01);
        assertEquals("Truck 10", payload.get("device_name").asText());
        assertEquals(-6.2, payload.get("latitude").asDouble(), 0.0001);
    }

    @Test
    public void recordsGeofenceEventsWithTheGeofenceName() throws Exception {
        addGroup(1, null, TENANT_A);
        addDevice(10, 1);
        Geofence geofence = new Geofence();
        geofence.setId(3);
        geofence.setName("Jakarta depot");
        geofences.put(3L, geofence);

        Event enter = new Event(Event.TYPE_GEOFENCE_ENTER, 10);
        enter.setGeofenceId(3);
        Event exit = new Event(Event.TYPE_GEOFENCE_EXIT, 10);
        exit.setGeofenceId(3);
        recorder.record(enter, position(10, 0));
        recorder.record(exit, position(10, 0));

        List<OptinexusOutboxEvent> rows = rows();
        assertEquals(List.of("optiradar.geofence.entered", "optiradar.geofence.exited"),
                rows.stream().map(OptinexusOutboxEvent::getEventKey).sorted().toList());
        JsonNode payload = data(rows.get(0)).get("payload");
        assertEquals(3, payload.get("geofence_id").asInt());
        assertEquals("Jakarta depot", payload.get("geofence_name").asText());
        assertNotEquals(rows.get(0).getEventUuid(), rows.get(1).getEventUuid());
    }

    @Test
    public void recordsDeviceOnlineAndOfflineWithoutAPosition() throws Exception {
        addGroup(1, null, TENANT_A);
        addDevice(10, 1);

        recorder.record(new Event(Event.TYPE_DEVICE_ONLINE, 10), null);
        recorder.record(new Event(Event.TYPE_DEVICE_OFFLINE, 10), null);

        List<OptinexusOutboxEvent> rows = rows();
        assertEquals(List.of("optiradar.device.offline", "optiradar.device.online"),
                rows.stream().map(OptinexusOutboxEvent::getEventKey).sorted().toList());
        assertNull(data(rows.get(0)).get("payload").get("latitude"));
        assertEquals("online", data(rows.get(0)).get("payload").get("status").asText());
        assertEquals("offline", data(rows.get(1)).get("payload").get("status").asText());
    }

    @Test
    public void aDeviceThatWentSilentCountsAsOfflineAndKeepsItsStatus() throws Exception {
        addGroup(1, null, TENANT_A);
        addDevice(10, 1);

        recorder.record(new Event(Event.TYPE_DEVICE_UNKNOWN, 10), null);

        OptinexusOutboxEvent row = rows().get(0);
        assertEquals("optiradar.device.offline", row.getEventKey());
        assertEquals("unknown", data(row).get("payload").get("status").asText());
    }

    @Test
    public void findsTheTenantOnAnAncestorGroup() throws Exception {
        addGroup(1, null, TENANT_A);
        addGroup(2, 1L, null);
        addGroup(3, 2L, null);
        addDevice(10, 3);

        recorder.record(new Event(Event.TYPE_DEVICE_ONLINE, 10), null);

        assertEquals(TENANT_A, rows().get(0).getTenantId());
    }

    @Test
    public void keepsTenantsApartWhenTheTenantIsWrittenInUpperCase() throws Exception {
        addGroup(1, null, TENANT_A.toUpperCase());
        addDevice(10, 1);

        recorder.record(new Event(Event.TYPE_DEVICE_ONLINE, 10), null);

        assertEquals(TENANT_A, rows().get(0).getTenantId());
    }

    @Test
    public void ignoresDevicesWithoutATenant() throws Exception {
        addGroup(1, null, null);
        addDevice(10, 1);
        addDevice(11, 0);

        recorder.record(new Event(Event.TYPE_DEVICE_ONLINE, 10), null);
        recorder.record(new Event(Event.TYPE_DEVICE_ONLINE, 11), null);
        recorder.record(new Event(Event.TYPE_DEVICE_ONLINE, 12), null);

        assertTrue(rows().isEmpty());
    }

    @Test
    public void ignoresATenantThatIsNotAnOptiNexusIdentifier() throws Exception {
        addGroup(1, null, "acme");
        addDevice(10, 1);

        recorder.record(new Event(Event.TYPE_DEVICE_ONLINE, 10), null);

        assertTrue(rows().isEmpty());
    }

    @Test
    public void ignoresEventsOptiNexusHasNoUseFor() throws Exception {
        addGroup(1, null, TENANT_A);
        addDevice(10, 1);

        for (String type : List.of(Event.TYPE_ALARM, Event.TYPE_IGNITION_ON, Event.TYPE_DEVICE_MOVING,
                Event.TYPE_COMMAND_RESULT)) {
            recorder.record(new Event(type, 10), position(10, 0));
        }

        assertTrue(rows().isEmpty());
    }

    @Test
    public void recordsNothingWhenReportingIsOff() throws Exception {
        addGroup(1, null, TENANT_A);
        addDevice(10, 1);

        newRecorder(false, storage).record(new Event(Event.TYPE_DEVICE_ONLINE, 10), null);

        assertTrue(rows().isEmpty());
    }

    @Test
    public void aFailingStorageNeverBreaksTheEventPipeline() throws Exception {
        addGroup(1, null, TENANT_A);
        addDevice(10, 1);
        Storage broken = mock(Storage.class);
        when(broken.addObject(any(), any())).thenThrow(new StorageException("database is down"));

        assertDoesNotThrow(() -> newRecorder(true, broken).record(new Event(Event.TYPE_DEVICE_ONLINE, 10), null));
    }

}
