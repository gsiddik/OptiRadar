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
package org.traccar.database;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.helper.UnitsConverter;
import org.traccar.model.Device;
import org.traccar.model.Event;
import org.traccar.model.Geofence;
import org.traccar.model.Group;
import org.traccar.model.OptinexusOutboxEvent;
import org.traccar.model.Position;
import org.traccar.session.cache.CacheManager;
import org.traccar.storage.Storage;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Request;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Turns the events worth reporting to OptiNexus into outbox rows. The row is written next to the event itself and
 * delivered later by {@link OptinexusEventRelay}, so an event is never lost because OptiNexus is down and the
 * processing of positions never waits for it.
 *
 * <p>A device that stopped reporting is "offline" for OptiNexus whether Traccar saw the connection close
 * (deviceOffline) or only no data within the status timeout (deviceUnknown); the payload keeps the difference in
 * {@code status}.
 *
 * <p>Only devices that belong to a tenant (a group, or an ancestor group, carrying the tenant identifier) are
 * reported: OptiNexus is told which tenant an event belongs to, and an event without one has nowhere to go.
 */
@Singleton
public class OptinexusEventRecorder {

    private static final Logger LOGGER = LoggerFactory.getLogger(OptinexusEventRecorder.class);

    private static final int MAX_GROUP_DEPTH = 10;

    static final Map<String, String> EVENT_KEYS = Map.of(
            Event.TYPE_DEVICE_ONLINE, "optiradar.device.online",
            Event.TYPE_DEVICE_OFFLINE, "optiradar.device.offline",
            Event.TYPE_DEVICE_UNKNOWN, "optiradar.device.offline",
            Event.TYPE_GEOFENCE_ENTER, "optiradar.geofence.entered",
            Event.TYPE_GEOFENCE_EXIT, "optiradar.geofence.exited",
            Event.TYPE_DEVICE_OVERSPEED, "optiradar.device.overspeed");

    private final Storage storage;
    private final CacheManager cacheManager;
    private final ObjectMapper objectMapper;
    private final boolean enabled;
    private final String tenantAttribute;

    @Inject
    public OptinexusEventRecorder(
            Config config, Storage storage, CacheManager cacheManager, ObjectMapper objectMapper) {
        this.storage = storage;
        this.cacheManager = cacheManager;
        this.objectMapper = objectMapper;
        this.enabled = config.getBoolean(Keys.OPTINEXUS_EVENTS_ENABLE);
        this.tenantAttribute = config.getString(Keys.OPENID_TENANT_GROUP_ATTRIBUTE);
    }

    public static String eventKeyOf(String eventType) {
        return EVENT_KEYS.get(eventType);
    }

    /**
     * Records the event for OptiNexus when it is one of the reported kinds and its device has a tenant. Never
     * throws: reporting is a side channel and must not disturb the processing of the event.
     */
    public void record(Event event, Position position) {
        if (!enabled) {
            return;
        }
        try {
            String eventKey = eventKeyOf(event.getType());
            if (eventKey == null) {
                return;
            }
            Device device = cacheManager.getObject(Device.class, event.getDeviceId());
            if (device == null) {
                return;
            }
            String tenantId = tenantOf(device);
            if (tenantId == null) {
                LOGGER.debug("Event {} of device {} has no tenant, not reported to OptiNexus",
                        event.getType(), device.getId());
                return;
            }

            OptinexusOutboxEvent row = new OptinexusOutboxEvent();
            row.setEventUuid(UUID.randomUUID().toString());
            row.setEventKey(eventKey);
            row.setTenantId(tenantId);
            row.setDeviceId(device.getId());
            row.setSourceEventId(event.getId());
            row.setOccurredAt(event.getEventTime() != null ? event.getEventTime() : new Date());
            row.setPayload(objectMapper.writeValueAsString(data(event, device, position)));
            row.setId(storage.addObject(row, new Request(new Columns.Exclude("id"))));
        } catch (Exception e) {
            LOGGER.warn("OptiNexus event not recorded", e);
        }
    }

    /**
     * The OptiNexus tenant of the device: the identifier on its group, else on the nearest ancestor group.
     * The identifier must be a UUID (that is what OptiNexus uses), anything else counts as no tenant.
     */
    String tenantOf(Device device) {
        long groupId = device.getGroupId();
        for (int depth = 0; groupId > 0 && depth < MAX_GROUP_DEPTH; depth++) {
            Group group = cacheManager.getObject(Group.class, groupId);
            if (group == null) {
                return null;
            }
            String value = group.getString(tenantAttribute);
            if (value != null && !value.isBlank()) {
                try {
                    return UUID.fromString(value.trim()).toString().toLowerCase(Locale.ROOT);
                } catch (IllegalArgumentException e) {
                    return null;
                }
            }
            groupId = group.getGroupId();
        }
        return null;
    }

    Map<String, Object> data(Event event, Device device, Position position) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("device_id", device.getId());
        payload.put("device_name", device.getName());
        payload.put("unique_id", device.getUniqueId());
        payload.put("event_time", event.getEventTime() != null ? event.getEventTime().toInstant().toString() : null);

        String status = switch (event.getType()) {
            case Event.TYPE_DEVICE_ONLINE -> Device.STATUS_ONLINE;
            case Event.TYPE_DEVICE_OFFLINE -> Device.STATUS_OFFLINE;
            case Event.TYPE_DEVICE_UNKNOWN -> Device.STATUS_UNKNOWN;
            default -> null;
        };
        if (status != null) {
            payload.put("status", status);
        }

        if (position != null) {
            payload.put("latitude", position.getLatitude());
            payload.put("longitude", position.getLongitude());
            payload.put("speed_kmh", kmh(position.getSpeed()));
            payload.put("fix_time",
                    position.getFixTime() != null ? position.getFixTime().toInstant().toString() : null);
        }

        if (event.getGeofenceId() != 0) {
            Geofence geofence = cacheManager.getObject(Geofence.class, event.getGeofenceId());
            payload.put("geofence_id", event.getGeofenceId());
            payload.put("geofence_name", geofence != null ? geofence.getName() : null);
        }

        if (Event.TYPE_DEVICE_OVERSPEED.equals(event.getType())) {
            payload.put("speed_kmh", kmh(event.getDouble("speed")));
            payload.put("speed_limit_kmh", kmh(event.getDouble(Position.KEY_SPEED_LIMIT)));
        }

        Map<String, Object> correlation = new LinkedHashMap<>();
        correlation.put("unique_id", device.getUniqueId());
        if (event.getPositionId() != 0) {
            correlation.put("position_id", event.getPositionId());
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("aggregate_type", "device");
        data.put("aggregate_id", String.valueOf(device.getId()));
        data.put("correlation", correlation);
        data.put("payload", payload);
        return data;
    }

    private static double kmh(double knots) {
        return Math.round(UnitsConverter.kphFromKnots(knots) * 10) / 10.0;
    }

}
