/*
 * Copyright 2026 Anton Tananaev (anton@traccar.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.telematics;

import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.database.DeviceTenants;
import org.traccar.handler.OutdatedHandler;
import org.traccar.model.Device;
import org.traccar.model.Group;
import org.traccar.model.Position;
import org.traccar.model.User;
import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The versioned, additive read model of what OptiRadar knows about each device right now (schema
 * {@code optiradar.telematics.latest}, version {@code 1.0}), for the products that need vehicle data from OptiRadar.
 *
 * <ul>
 * <li><b>Latest, not history.</b> One entry per device: the most recent state OptiRadar holds. No history is stored
 * for this read model, none is implied, and a consumer that polls gets samples of the latest state, not a series.</li>
 * <li><b>Times are explicit and separate.</b> {@code measured_at} is when the device measured the values (its own
 * report time, else the fix time, else - flagged by {@code time_source} - the time OptiRadar received it);
 * {@code received_at} is when OptiRadar received them; {@code fix_time} is when the location was fixed. A position
 * without a new fix repeats the old fix time, so the fix time is never used as the time of an odometer value.</li>
 * <li><b>Units are explicit.</b> OptiRadar stores speed in knots, distances in metres and hours in milliseconds; this
 * model says {@code km}, {@code km/h}, {@code h}, {@code percent}, {@code V}, {@code L} next to every value and
 * converts exactly (decimal strings, fixed scale, half-up).</li>
 * <li><b>Absent stays absent.</b> A value the device did not report is not in the answer: never zero, never
 * "unknown", never copied from an earlier report. A device that never reported has {@code latest: null}.</li>
 * <li><b>Tenant comes from ownership.</b> The tenant of an entry is the one named on the device's group (or the
 * nearest ancestor group); devices of no tenant are not exported (only counted). The caller never says which tenant;
 * {@code tenant_id} as a parameter only narrows what the caller may already read.</li>
 * <li><b>Ordering.</b> OptiRadar never moves a device's latest position back to an older fix. A consumer keeps the
 * entry with the larger ({@code measured_at}, {@code position_id}) and ignores an older one that arrives late.</li>
 * <li><b>Location is opt-in.</b> Coordinates, speed and course are only included with {@code include=location}.</li>
 * </ul>
 */
@Singleton
public class TelematicsSnapshot {

    public static final String SCHEMA = "optiradar.telematics.latest";
    public static final String SCHEMA_VERSION = "1.0";
    public static final int MAX_LIMIT = 1000;
    public static final int DEFAULT_LIMIT = 500;

    private static final long CLOCK_AHEAD_SECONDS = 300;
    private static final BigDecimal KNOT_KMH = new BigDecimal("1.852");
    private static final BigDecimal METRES_PER_KM = new BigDecimal(1000);
    private static final BigDecimal MILLIS_PER_HOUR = new BigDecimal(3_600_000);
    private static final BigDecimal HUNDRED = new BigDecimal(100);

    /**
     * What the caller asked for.
     *
     * @param after the last device id of the previous page (0 for the first)
     * @param limit devices per page, 1 to {@link #MAX_LIMIT}
     * @param includeLocation add the location block (coordinates, speed, course)
     * @param tenantId only devices of this tenant (a lower-case UUID), or null
     */
    public record Query(long after, int limit, boolean includeLocation, String tenantId) {
    }

    private final Storage storage;
    private final String tenantAttribute;
    private final long staleSeconds;

    @Inject
    public TelematicsSnapshot(Config config, Storage storage) {
        this.storage = storage;
        this.tenantAttribute = config.getString(Keys.OPENID_TENANT_GROUP_ATTRIBUTE);
        this.staleSeconds = Math.max(1, config.getLong(Keys.TELEMATICS_STALE_SECONDS));
    }

    protected Instant now() {
        return Instant.now();
    }

    /**
     * One page of the latest state of the devices {@code userId} may read.
     */
    public Map<String, Object> latest(long userId, Query query) throws StorageException {
        Instant generated = now();
        int limit = Math.max(1, Math.min(MAX_LIMIT, query.limit()));

        List<Device> devices = storage.getObjects(Device.class, new Request(
                new Columns.All(), new Condition.Permission(User.class, userId, Device.class)));
        Map<Long, Group> groups = new HashMap<>();
        for (Group group : storage.getObjects(Group.class, new Request(new Columns.All()))) {
            groups.put(group.getId(), group);
        }
        Map<Long, Position> positions = new HashMap<>();
        for (Position position : storage.getObjects(Position.class, new Request(
                new Columns.All(), new Condition.LatestPositions()))) {
            positions.put(position.getDeviceId(), position);
        }

        List<Map<String, Object>> items = new ArrayList<>();
        int noTenant = 0;
        long last = 0;
        boolean more = false;
        for (Device device : devices.stream().sorted(Comparator.comparingLong(Device::getId)).toList()) {
            if (device.getId() <= query.after()) {
                continue;
            }
            String tenant = DeviceTenants.tenantOf(device, groups::get, tenantAttribute);
            if (tenant == null) {
                noTenant++;
                continue;
            }
            if (query.tenantId() != null && !query.tenantId().equals(tenant)) {
                continue;
            }
            if (items.size() == limit) {
                more = true;
                break;
            }
            items.add(item(device, tenant, positions.get(device.getId()), generated, query.includeLocation()));
            last = device.getId();
        }

        Map<String, Object> page = new LinkedHashMap<>();
        page.put("schema", SCHEMA);
        page.put("schema_version", SCHEMA_VERSION);
        page.put("source", "optiradar");
        page.put("generated_at", generated.toString());
        page.put("semantics", Map.of(
                "state", "latest_per_device",
                "history", "not_provided",
                "ordering", "keep the larger (measured_at, position_id) per device_ref",
                "absent_values", "omitted, never zero-filled"));
        page.put("stale_after_seconds", staleSeconds);
        page.put("items", items);
        page.put("next_cursor", more ? String.valueOf(last) : null);
        page.put("skipped", Map.of("no_tenant", noTenant));
        return page;
    }

    Map<String, Object> item(Device device, String tenant, Position position, Instant generated, boolean location) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("device_ref", String.valueOf(device.getId()));
        item.put("unique_id", device.getUniqueId());
        item.put("name", device.getName());
        item.put("tenant_id", tenant);
        String registration = firstText(device.getAttributes().get("registrationNumber"),
                device.getAttributes().get("plate"));
        if (registration != null) {
            item.put("registration_number", registration);
        }
        item.put("device_status", device.getStatus());
        if (device.getLastUpdate() != null) {
            item.put("last_update", device.getLastUpdate().toInstant().toString());
        }
        item.put("latest", position != null ? latest(position, generated, location) : null);
        return item;
    }

    private Map<String, Object> latest(Position position, Instant generated, boolean location) {
        Map<String, Object> latest = new LinkedHashMap<>();
        latest.put("position_id", position.getId());

        Instant fix = fixTime(position);
        Instant device = position.getDeviceTime() != null ? position.getDeviceTime().toInstant() : null;
        Instant received = position.getServerTime() != null ? position.getServerTime().toInstant() : null;
        Instant measured;
        String source;
        if (device != null) {
            measured = device;
            source = "device";
        } else if (fix != null) {
            measured = fix;
            source = "fix";
        } else {
            measured = received;
            source = "server";
        }
        if (measured != null) {
            latest.put("measured_at", measured.toString());
            latest.put("time_source", source);
            long age = generated.getEpochSecond() - measured.getEpochSecond();
            latest.put("age_seconds", Math.max(0, age));
            latest.put("stale", age > staleSeconds);
            if (-age > CLOCK_AHEAD_SECONDS) {
                latest.put("clock_ahead", true);
            }
        }
        if (received != null) {
            latest.put("received_at", received.toString());
        }
        if (fix != null) {
            latest.put("fix_time", fix.toString());
        }

        Map<String, Object> metrics = metrics(position.getAttributes());
        if (!metrics.isEmpty()) {
            latest.put("metrics", metrics);
        }
        if (location) {
            Map<String, Object> place = location(position, fix);
            if (place != null) {
                latest.put("location", place);
            }
        }
        return latest;
    }

    /**
     * The time of the location fix, or null when the device never had one (OptiRadar then holds no time or the start
     * of GPS time).
     */
    static Instant fixTime(Position position) {
        Date fix = position.getFixTime();
        return fix != null && fix.getTime() > OutdatedHandler.GPS_EPOCH ? fix.toInstant() : null;
    }

    private Map<String, Object> location(Position position, Instant fix) {
        boolean placed = position.getLatitude() != 0 || position.getLongitude() != 0;
        if (fix == null && !placed) {
            return null;
        }
        if (Math.abs(position.getLatitude()) > 90 || Math.abs(position.getLongitude()) > 180) {
            return null;
        }
        Map<String, Object> place = new LinkedHashMap<>();
        place.put("latitude", position.getLatitude());
        place.put("longitude", position.getLongitude());
        place.put("valid", position.getValid());
        if (position.getAccuracy() > 0) {
            place.put("accuracy_m", scaled(BigDecimal.valueOf(position.getAccuracy()), 1));
        }
        if (position.getSpeed() >= 0 && Double.isFinite(position.getSpeed())) {
            place.put("speed_kmh", scaled(BigDecimal.valueOf(position.getSpeed()).multiply(KNOT_KMH), 2));
        }
        if (position.getCourse() >= 0 && position.getCourse() <= 360) {
            place.put("course_deg", scaled(BigDecimal.valueOf(position.getCourse()), 1));
        }
        return place;
    }

    /**
     * The device-reported values that have a meaning for other products, converted to explicit units. Only what the
     * device reported and what is plausible is returned; the rest is left out.
     */
    static Map<String, Object> metrics(Map<String, Object> attributes) {
        Map<String, Object> metrics = new LinkedHashMap<>();
        BigDecimal odometer = number(attributes.get(Position.KEY_ODOMETER));
        if (odometer != null && odometer.signum() >= 0) {
            metrics.put("odometer", quantity(odometer.divide(METRES_PER_KM), 3, "km", "DEVICE_ODOMETER"));
        }
        BigDecimal distance = number(attributes.get(Position.KEY_TOTAL_DISTANCE));
        if (distance != null && distance.signum() >= 0) {
            metrics.put("gps_distance", quantity(distance.divide(METRES_PER_KM), 3, "km", "GPS_DISTANCE"));
        }
        BigDecimal hours = number(attributes.get(Position.KEY_HOURS));
        if (hours != null && hours.signum() >= 0) {
            metrics.put("engine_hours", quantity(hours.divide(MILLIS_PER_HOUR, 6, RoundingMode.HALF_UP), 3, "h", null));
        }
        Boolean ignition = bool(attributes.get(Position.KEY_IGNITION));
        if (ignition != null) {
            metrics.put("ignition", ignition);
        }
        percent(metrics, "battery_level", attributes.get(Position.KEY_BATTERY_LEVEL));
        percent(metrics, "fuel_level", attributes.get(Position.KEY_FUEL_LEVEL));
        BigDecimal fuel = number(attributes.get(Position.KEY_FUEL));
        if (fuel != null && fuel.signum() >= 0) {
            metrics.put("fuel", quantity(fuel, 2, "L", null));
        }
        BigDecimal power = number(attributes.get(Position.KEY_POWER));
        if (power != null && power.signum() >= 0) {
            metrics.put("external_voltage", quantity(power, 3, "V", null));
        }
        BigDecimal battery = number(attributes.get(Position.KEY_BATTERY));
        if (battery != null && battery.signum() >= 0) {
            metrics.put("battery_voltage", quantity(battery, 3, "V", null));
        }
        return metrics;
    }

    private static void percent(Map<String, Object> metrics, String name, Object raw) {
        BigDecimal value = number(raw);
        if (value != null && value.signum() >= 0 && value.compareTo(HUNDRED) <= 0) {
            metrics.put(name, quantity(value, 1, "percent", null));
        }
    }

    private static Map<String, Object> quantity(BigDecimal value, int scale, String unit, String kind) {
        Map<String, Object> quantity = new LinkedHashMap<>();
        quantity.put("value", scaled(value, scale));
        quantity.put("unit", unit);
        if (kind != null) {
            quantity.put("kind", kind);
        }
        return quantity;
    }

    private static String scaled(BigDecimal value, int scale) {
        return value.setScale(scale, RoundingMode.HALF_UP).toPlainString();
    }

    /**
     * A finite number from a number or a numeric text, else null. Never zero for "not there".
     */
    static BigDecimal number(Object raw) {
        if (raw instanceof Number number) {
            double value = number.doubleValue();
            if (Double.isNaN(value) || Double.isInfinite(value)) {
                return null;
            }
            return raw instanceof Long || raw instanceof Integer
                    ? BigDecimal.valueOf(number.longValue()) : new BigDecimal(Double.toString(value));
        }
        if (raw instanceof String text && !text.isBlank() && text.trim().length() <= 32) {
            try {
                return new BigDecimal(text.trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    static Boolean bool(Object raw) {
        if (raw instanceof Boolean value) {
            return value;
        }
        if (raw instanceof String text) {
            String value = text.trim().toLowerCase(Locale.ROOT);
            if (value.equals("true")) {
                return true;
            }
            if (value.equals("false")) {
                return false;
            }
        }
        return null;
    }

    private static String firstText(Object... values) {
        for (Object value : values) {
            if (value instanceof String text && !text.isBlank()) {
                return text.trim();
            }
        }
        return null;
    }

}
