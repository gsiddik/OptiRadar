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

import org.traccar.model.Device;
import org.traccar.model.Group;

import java.util.Locale;
import java.util.UUID;
import java.util.function.LongFunction;

/**
 * Who owns a device: the OptiNexus tenant named on its group, else on the nearest ancestor group. This is the only
 * source of a tenant for anything that leaves OptiRadar (events, telematics): never a value sent by a client.
 */
public final class DeviceTenants {

    private static final int MAX_GROUP_DEPTH = 10;

    private DeviceTenants() {
    }

    /**
     * The tenant identifier of the device (a lower-case UUID, which is what OptiNexus uses), or null when no group on
     * the way up carries one or the value is not a UUID.
     */
    public static String tenantOf(Device device, LongFunction<Group> groups, String attribute) {
        long groupId = device.getGroupId();
        for (int depth = 0; groupId > 0 && depth < MAX_GROUP_DEPTH; depth++) {
            Group group = groups.apply(groupId);
            if (group == null) {
                return null;
            }
            String value = group.getString(attribute);
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

}
