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
package org.traccar.api.resource;

import org.traccar.api.BaseResource;
import org.traccar.governance.Catalog;
import org.traccar.governance.Governed;
import org.traccar.storage.StorageException;
import org.traccar.telematics.TelematicsSnapshot;

import jakarta.inject.Inject;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * The versioned telematics read model (see {@link TelematicsSnapshot}): the latest state of the devices the caller may
 * read, with explicit times, units and tenant. Read only; the tenant is derived from device ownership, never taken from
 * the request.
 */
@Governed(value = Catalog.LIVE_VIEW, integration = true)
@Path("telematics")
@Produces(MediaType.APPLICATION_JSON)
public class TelematicsResource extends BaseResource {

    @Inject
    private TelematicsSnapshot snapshot;

    /**
     * @param after the {@code next_cursor} of the previous page
     * @param limit devices per page (1 to 1000, default 500)
     * @param include {@code location} to add coordinates, speed and course (left out by default)
     * @param tenantId only devices of this tenant, among the ones the caller may read
     */
    @Path("v1/latest")
    @GET
    public Map<String, Object> latest(
            @QueryParam("after") @DefaultValue("0") long after,
            @QueryParam("limit") @DefaultValue("500") int limit,
            @QueryParam("include") String include,
            @QueryParam("tenant_id") String tenantId) throws StorageException {
        boolean location = false;
        if (include != null && !include.isBlank()) {
            if (!include.trim().equalsIgnoreCase("location")) {
                throw new IllegalArgumentException("include can only be 'location'");
            }
            location = true;
        }
        String tenant = null;
        if (tenantId != null && !tenantId.isBlank()) {
            try {
                tenant = UUID.fromString(tenantId.trim()).toString().toLowerCase(Locale.ROOT);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("tenant_id must be a tenant identifier");
            }
        }
        if (after < 0 || limit < 1 || limit > TelematicsSnapshot.MAX_LIMIT) {
            throw new IllegalArgumentException("after must not be negative and limit must be 1 to "
                    + TelematicsSnapshot.MAX_LIMIT);
        }
        return snapshot.latest(getUserId(), new TelematicsSnapshot.Query(after, limit, location, tenant));
    }

}
