package org.traccar.telematics;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.handler.OutdatedHandler;
import org.traccar.model.AttributeMap;
import org.traccar.model.Device;
import org.traccar.model.Group;
import org.traccar.model.Permission;
import org.traccar.model.Position;
import org.traccar.model.User;
import org.traccar.storage.MemoryStorage;
import org.traccar.storage.Storage;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TelematicsSnapshotTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String TENANT_A = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";
    private static final String TENANT_B = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c02";
    private static final Instant NOW = Instant.parse("2026-10-17T10:00:00Z");

    private Storage storage;
    private TelematicsSnapshot snapshot;
    private Group groupA;
    private Group groupB;
    private Group childOfA;
    private Group noTenant;
    private User reader;

    private long add(Object entity) throws Exception {
        return storage.addObject(entity, new Request(new Columns.Exclude("id")));
    }

    private Group group(String name, String tenant, long parent) throws Exception {
        Group group = new Group();
        group.setName(name);
        group.setGroupId(parent);
        if (tenant != null) {
            group.set("optinexusTenantId", tenant);
        }
        group.setId(add(group));
        return group;
    }

    private Device device(String name, Group group) throws Exception {
        Device device = new Device();
        device.setName(name);
        device.setUniqueId("imei-" + name);
        device.setGroupId(group != null ? group.getId() : 0);
        device.setId(add(device));
        storage.addPermission(new Permission(User.class, reader.getId(), Device.class, device.getId()));
        return device;
    }

    private Position position(Device device, Date deviceTime, Date fixTime, Date serverTime, Map<String, Object> attributes)
            throws Exception {
        Position position = new Position();
        position.setDeviceId(device.getId());
        position.setProtocol("osmand");
        position.setDeviceTime(deviceTime);
        position.setFixTime(fixTime);
        position.setServerTime(serverTime);
        position.setValid(true);
        position.setLatitude(-6.2);
        position.setLongitude(106.8);
        position.setSpeed(10);
        position.setCourse(90);
        position.setAttributes(new AttributeMap(attributes));
        position.setId(add(position));
        Device update = new Device();
        update.setId(device.getId());
        update.setPositionId(position.getId());
        storage.updateObject(update, new Request(new Columns.Include("positionId"),
                new Condition.Equals("id", device.getId())));
        return position;
    }

    private Position fresh(Device device, Map<String, Object> attributes) throws Exception {
        Date t = Date.from(NOW.minusSeconds(30));
        return position(device, t, t, Date.from(NOW.minusSeconds(29)), attributes);
    }

    private Map<String, Object> page(long after, int limit, boolean location, String tenant) throws Exception {
        return snapshot.latest(reader.getId(), new TelematicsSnapshot.Query(after, limit, location, tenant));
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> items(Map<String, Object> page) {
        return (List<Map<String, Object>>) page.get("items");
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> latest(Map<String, Object> item) {
        return (Map<String, Object>) item.get("latest");
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> metrics(Map<String, Object> item) {
        return (Map<String, Object>) latest(item).get("metrics");
    }

    @BeforeEach
    public void setUp() throws Exception {
        storage = new MemoryStorage();
        snapshot = snapshot(new Config());
        reader = new User();
        reader.setLogin("connector");
        reader.setReadonly(true);
        reader.setId(add(reader));
        groupA = group("A", TENANT_A, 0);
        groupB = group("B", TENANT_B, 0);
        childOfA = group("A depot", null, groupA.getId());
        noTenant = group("Nobody", null, 0);
    }

    private TelematicsSnapshot snapshot(Config config) {
        return new TelematicsSnapshot(config, storage) {
            @Override
            protected Instant now() {
                return NOW;
            }
        };
    }

    // ---------------------------------------------------------------------------------------------------------
    // Tenant from ownership

    @Test
    public void theTenantIsTheOneOnTheGroupOrTheNearestAncestorNeverTheDevice() throws Exception {
        Device own = device("own", groupA);
        Device nested = device("nested", childOfA);
        Device other = device("other", groupB);
        Device claimed = device("claimed", groupB);
        claimed.set("optinexusTenantId", TENANT_A);   // a claim on the device itself counts for nothing
        storage.updateObject(claimed, new Request(new Columns.All(), new Condition.Equals("id", claimed.getId())));
        for (Device device : List.of(own, nested, other, claimed)) {
            fresh(device, Map.of());
        }

        Map<String, String> tenants = items(page(0, 100, false, null)).stream().collect(Collectors.toMap(
                item -> (String) item.get("name"), item -> (String) item.get("tenant_id")));

        assertEquals(TENANT_A, tenants.get("own"));
        assertEquals(TENANT_A, tenants.get("nested"));
        assertEquals(TENANT_B, tenants.get("other"));
        assertEquals(TENANT_B, tenants.get("claimed"));
    }

    @Test
    public void devicesWithoutATenantAreNotExportedOnlyCounted() throws Exception {
        fresh(device("loose", null), Map.of());
        fresh(device("nobody", noTenant), Map.of());
        Group broken = group("Broken", "not-a-tenant-id", 0);
        fresh(device("broken", broken), Map.of());
        fresh(device("mine", groupA), Map.of());

        Map<String, Object> result = page(0, 100, false, null);

        assertEquals(1, items(result).size());
        assertEquals("mine", items(result).get(0).get("name"));
        assertEquals(Map.of("no_tenant", 3), result.get("skipped"));
    }

    @Test
    public void theTenantFilterOnlyNarrowsAndNeverAddsDevices() throws Exception {
        fresh(device("a", groupA), Map.of());
        fresh(device("b", groupB), Map.of());

        assertEquals(List.of("a"), items(page(0, 100, false, TENANT_A)).stream().map(i -> i.get("name")).toList());
        assertEquals(List.of("b"), items(page(0, 100, false, TENANT_B)).stream().map(i -> i.get("name")).toList());
        assertEquals(2, items(page(0, 100, false, null)).size());
        assertTrue(items(page(0, 100, false, "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c09")).isEmpty());
    }

    @Test
    public void aTenantUserOnlySeesTheirOwnDevicesWhateverTheyAsk() throws Exception {
        fresh(device("a", groupA), Map.of());
        fresh(device("b", groupB), Map.of());
        User alice = new User();
        alice.setLogin("alice");
        alice.setId(add(alice));
        storage.addPermission(new Permission(User.class, alice.getId(), Group.class, groupA.getId()));

        Map<String, Object> asAlice = snapshot.latest(alice.getId(),
                new TelematicsSnapshot.Query(0, 100, false, TENANT_B));
        assertTrue(items(asAlice).isEmpty(), "asking for another tenant does not reveal it");
        asAlice = snapshot.latest(alice.getId(), new TelematicsSnapshot.Query(0, 100, false, null));
        assertEquals(List.of("a"), items(asAlice).stream().map(i -> i.get("name")).toList());
    }

    // ---------------------------------------------------------------------------------------------------------
    // Latest, absent and quality

    @Test
    public void aDeviceThatNeverReportedHasNoLatestAndNothingIsInvented() throws Exception {
        device("silent", groupA);

        Map<String, Object> item = items(page(0, 10, true, null)).get(0);

        assertTrue(item.containsKey("latest"));
        assertNull(item.get("latest"));
        assertEquals("offline", item.get("device_status"));
        assertFalse(item.containsKey("last_update"));
    }

    @Test
    public void valuesTheDeviceDidNotReportAreOmittedNeverZero() throws Exception {
        fresh(device("bare", groupA), Map.of());
        fresh(device("partial", groupA), Map.of("odometer", 1500, "ignition", false));

        List<Map<String, Object>> items = items(page(0, 10, false, null));

        assertFalse(latest(items.get(0)).containsKey("metrics"));
        Map<String, Object> metrics = metrics(items.get(1));
        assertEquals(Set.of("odometer", "ignition"), metrics.keySet());
        assertEquals(false, metrics.get("ignition"));
        assertEquals("1.500", ((Map<?, ?>) metrics.get("odometer")).get("value"));
    }

    @Test
    public void aRealZeroIsKeptButNonsenseIsDropped() throws Exception {
        fresh(device("zero", groupA), Map.of("odometer", 0, "totalDistance", -5, "fuelLevel", 140,
                "batteryLevel", 87.5, "fuel", "abc", "power", Double.NaN, "hours", Double.POSITIVE_INFINITY));

        Map<String, Object> metrics = metrics(items(page(0, 10, false, null)).get(0));

        assertEquals(Set.of("odometer", "battery_level"), metrics.keySet());
        assertEquals("0.000", ((Map<?, ?>) metrics.get("odometer")).get("value"));
        assertEquals("87.5", ((Map<?, ?>) metrics.get("battery_level")).get("value"));
    }

    @Test
    public void unitsAreExplicitAndConversionsAreExactDecimals() throws Exception {
        fresh(device("units", groupA), Map.of("odometer", 123456789.4, "totalDistance", "2500.5",
                "hours", 5_400_000L, "fuel", 41.256, "power", 12.4567, "battery", 3.9, "fuelLevel", 63));

        Map<String, Object> metrics = metrics(items(page(0, 10, false, null)).get(0));

        assertEquals(Map.of("value", "123456.789", "unit", "km", "kind", "DEVICE_ODOMETER"), metrics.get("odometer"));
        assertEquals(Map.of("value", "2.501", "unit", "km", "kind", "GPS_DISTANCE"), metrics.get("gps_distance"));
        assertEquals(Map.of("value", "1.500", "unit", "h"), metrics.get("engine_hours"));
        assertEquals(Map.of("value", "41.26", "unit", "L"), metrics.get("fuel"));
        assertEquals(Map.of("value", "12.457", "unit", "V"), metrics.get("external_voltage"));
        assertEquals(Map.of("value", "3.900", "unit", "V"), metrics.get("battery_voltage"));
        assertEquals(Map.of("value", "63.0", "unit", "percent"), metrics.get("fuel_level"));
    }

    @Test
    public void numericAndBooleanTextIsUnderstoodOtherTextIsNot() {
        assertEquals("12.5", TelematicsSnapshot.number(" 12.5 ").toPlainString());
        assertNull(TelematicsSnapshot.number("12,5"));
        assertNull(TelematicsSnapshot.number(""));
        assertNull(TelematicsSnapshot.number(null));
        assertNull(TelematicsSnapshot.number(true));
        assertNull(TelematicsSnapshot.number("9".repeat(40)));
        assertEquals(Boolean.TRUE, TelematicsSnapshot.bool("TRUE"));
        assertEquals(Boolean.FALSE, TelematicsSnapshot.bool("false"));
        assertNull(TelematicsSnapshot.bool("1"));
        assertNull(TelematicsSnapshot.bool(1));
    }

    // ---------------------------------------------------------------------------------------------------------
    // Time

    @Test
    public void aReportWithoutANewFixIsMeasuredWhenTheDeviceSentItNotWhenTheOldFixWas() throws Exception {
        Device device = device("outdated", groupA);
        Date oldFix = Date.from(NOW.minusSeconds(86_400));
        Date sent = Date.from(NOW.minusSeconds(20));
        position(device, sent, oldFix, Date.from(NOW.minusSeconds(19)), Map.of("odometer", 2000));

        Map<String, Object> latest = latest(items(page(0, 10, false, null)).get(0));

        assertEquals(sent.toInstant().toString(), latest.get("measured_at"));
        assertEquals("device", latest.get("time_source"));
        assertEquals(oldFix.toInstant().toString(), latest.get("fix_time"));
        assertEquals(NOW.minusSeconds(19).toString(), latest.get("received_at"));
        assertEquals(20L, latest.get("age_seconds"));
        assertEquals(false, latest.get("stale"));
    }

    @Test
    public void theTimeFallsBackToTheFixAndThenToTheReceiveTimeAndSaysSo() throws Exception {
        Device byFix = device("fix", groupA);
        position(byFix, null, Date.from(NOW.minusSeconds(100)), Date.from(NOW.minusSeconds(90)), Map.of());
        Device byServer = device("server", groupA);
        position(byServer, null, new Date(OutdatedHandler.GPS_EPOCH), Date.from(NOW.minusSeconds(60)), Map.of());

        List<Map<String, Object>> items = items(page(0, 10, false, null));

        assertEquals("fix", latest(items.get(0)).get("time_source"));
        assertEquals(NOW.minusSeconds(100).toString(), latest(items.get(0)).get("measured_at"));
        assertEquals("server", latest(items.get(1)).get("time_source"));
        assertEquals(NOW.minusSeconds(60).toString(), latest(items.get(1)).get("measured_at"));
        assertFalse(latest(items.get(1)).containsKey("fix_time"), "the start of GPS time is not a fix");
    }

    @Test
    public void oldMeasurementsAreLabelledStaleNotDropped() throws Exception {
        Device device = device("old", groupA);
        Date old = Date.from(NOW.minusSeconds(901));
        position(device, old, old, old, Map.of("odometer", 3000));

        Map<String, Object> result = page(0, 10, false, null);
        Map<String, Object> latest = latest(items(result).get(0));

        assertEquals(true, latest.get("stale"));
        assertEquals(901L, latest.get("age_seconds"));
        assertEquals(900L, result.get("stale_after_seconds"));
        assertNotNull(metrics(items(result).get(0)).get("odometer"));

        Config config = new Config();
        config.setString(Keys.TELEMATICS_STALE_SECONDS, "1000");
        TelematicsSnapshot lenient = snapshot(config);
        Map<String, Object> again = lenient.latest(reader.getId(), new TelematicsSnapshot.Query(0, 10, false, null));
        assertEquals(false, latest(items(again).get(0)).get("stale"));
    }

    @Test
    public void aDeviceClockInTheFutureIsFlaggedAndNeverNegative() throws Exception {
        Device device = device("future", groupA);
        Date future = Date.from(NOW.plusSeconds(3600));
        position(device, future, future, Date.from(NOW.minusSeconds(1)), Map.of());

        Map<String, Object> latest = latest(items(page(0, 10, false, null)).get(0));

        assertEquals(0L, latest.get("age_seconds"));
        assertEquals(true, latest.get("clock_ahead"));
    }

    @Test
    public void onlyThePositionTheDevicePointsToIsReportedAnOlderOneArrivingLateChangesNothing() throws Exception {
        Device device = device("late", groupA);
        Position newest = position(device, Date.from(NOW.minusSeconds(10)), Date.from(NOW.minusSeconds(10)),
                Date.from(NOW.minusSeconds(9)), Map.of("odometer", 9000));
        Position older = new Position();
        older.setDeviceId(device.getId());
        older.setDeviceTime(Date.from(NOW.minusSeconds(500)));
        older.setFixTime(Date.from(NOW.minusSeconds(500)));
        older.setServerTime(Date.from(NOW.minusSeconds(5)));
        older.setAttributes(new AttributeMap(Map.of("odometer", 100)));
        older.setId(add(older));   // stored later, but Radar does not move the latest pointer back

        Map<String, Object> latest = latest(items(page(0, 10, false, null)).get(0));

        assertEquals(newest.getId(), latest.get("position_id"));
        assertEquals("9.000", ((Map<?, ?>) metrics(items(page(0, 10, false, null)).get(0)).get("odometer"))
                .get("value"));
    }

    // ---------------------------------------------------------------------------------------------------------
    // Location is opt-in

    @Test
    public void locationIsOnlyIncludedWhenAskedFor() throws Exception {
        fresh(device("place", groupA), Map.of("odometer", 1000));

        Map<String, Object> without = latest(items(page(0, 10, false, null)).get(0));
        Map<String, Object> with = latest(items(page(0, 10, true, null)).get(0));

        assertFalse(without.containsKey("location"));
        @SuppressWarnings("unchecked")
        Map<String, Object> place = (Map<String, Object>) with.get("location");
        assertEquals(-6.2, place.get("latitude"));
        assertEquals(106.8, place.get("longitude"));
        assertEquals(true, place.get("valid"));
        assertEquals("18.52", place.get("speed_kmh"));
        assertEquals("90.0", place.get("course_deg"));
        assertFalse(place.containsKey("accuracy_m"), "no accuracy reported, none invented");
    }

    @Test
    public void aDeviceThatNeverHadAFixHasNoLocationNotNullIsland() throws Exception {
        Device device = device("nofix", groupA);
        Position position = new Position();
        position.setDeviceId(device.getId());
        position.setDeviceTime(Date.from(NOW.minusSeconds(5)));
        position.setFixTime(new Date(OutdatedHandler.GPS_EPOCH));
        position.setServerTime(Date.from(NOW.minusSeconds(4)));
        position.setAttributes(new AttributeMap(Map.of("odometer", 10)));
        position.setId(add(position));
        Device update = new Device();
        update.setId(device.getId());
        update.setPositionId(position.getId());
        storage.updateObject(update, new Request(new Columns.Include("positionId"),
                new Condition.Equals("id", device.getId())));

        Map<String, Object> latest = latest(items(page(0, 10, true, null)).get(0));

        assertFalse(latest.containsKey("location"));
        assertNotNull(latest.get("metrics"));
    }

    // ---------------------------------------------------------------------------------------------------------
    // Pages and format

    @Test
    public void pagesFollowTheCursorInDeviceOrderWithoutGapsOrRepeats() throws Exception {
        List<Long> created = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            Device device = device("d" + i, i % 2 == 0 ? groupA : groupB);
            fresh(device, Map.of());
            created.add(device.getId());
        }
        device("loose", null);

        List<Long> seen = new ArrayList<>();
        long after = 0;
        int pages = 0;
        while (true) {
            Map<String, Object> result = page(after, 3, false, null);
            items(result).forEach(item -> seen.add(Long.parseLong((String) item.get("device_ref"))));
            pages++;
            if (result.get("next_cursor") == null) {
                break;
            }
            after = Long.parseLong((String) result.get("next_cursor"));
        }

        assertEquals(created, seen);
        assertEquals(3, pages);
    }

    @Test
    public void theLimitIsBoundedAndALastFullPageHasNoCursor() throws Exception {
        for (int i = 0; i < 3; i++) {
            fresh(device("d" + i, groupA), Map.of());
        }
        assertNull(page(0, 3, false, null).get("next_cursor"));
        assertNotNull(page(0, 2, false, null).get("next_cursor"));
        assertEquals(3, items(page(0, 100_000, false, null)).size());
        assertEquals(1, items(page(0, 0, false, null)).size(), "a limit below one is raised to one");
    }

    @Test
    public void theAnswerStatesItsSchemaVersionAndThatItIsNotHistory() throws Exception {
        fresh(device("one", groupA), Map.of("odometer", 1));

        Map<String, Object> result = page(0, 10, false, null);
        JsonNode json = MAPPER.readTree(MAPPER.writeValueAsString(result));

        assertEquals("optiradar.telematics.latest", json.get("schema").asText());
        assertEquals("1.0", json.get("schema_version").asText());
        assertEquals("optiradar", json.get("source").asText());
        assertEquals(NOW.toString(), json.get("generated_at").asText());
        assertEquals("latest_per_device", json.get("semantics").get("state").asText());
        assertEquals("not_provided", json.get("semantics").get("history").asText());
        assertTrue(json.get("items").get(0).get("latest").get("position_id").isNumber());
        assertTrue(json.get("items").get(0).get("latest").get("metrics").has("odometer"));
        assertTrue(json.get("next_cursor").isNull());
    }

    @Test
    public void theRegistrationNumberIsTakenFromTheDeviceAttributesWhenPresent() throws Exception {
        Device device = device("plate", groupA);
        device.set("registrationNumber", " B 1234 XYZ ");
        storage.updateObject(device, new Request(new Columns.All(), new Condition.Equals("id", device.getId())));
        Device none = device("none", groupA);
        none.set("plate", "  ");
        storage.updateObject(none, new Request(new Columns.All(), new Condition.Equals("id", none.getId())));

        List<Map<String, Object>> items = items(page(0, 10, false, null));

        assertEquals("B 1234 XYZ", items.get(0).get("registration_number"));
        assertFalse(items.get(1).containsKey("registration_number"));
    }

}
