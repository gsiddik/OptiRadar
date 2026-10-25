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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.storage.StorageException;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.util.UUID;

/**
 * Acts on the tenant events OptiNexus publishes through its event broker. When OptiRadar is assigned to a tenant
 * ({@value #ASSIGNED}) the tenant's group is created at once, so an operator can register the tenant's devices before
 * anybody from that tenant has signed in. Everything else (other events, other applications) is ignored, and nothing is
 * ever deleted: removing an application from a tenant leaves the group and its devices alone.
 */
@Singleton
public class OptinexusTenantEvents {

    public static final String ASSIGNED = "cgo.tenant.application_assigned";

    public static final String IGNORED = "ignored";

    public static final String CREATED = "group_created";

    public static final String EXISTS = "group_exists";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final OpenIdTenantLinker linker;
    private final String applicationCode;

    @Inject
    public OptinexusTenantEvents(Config config, OpenIdTenantLinker linker) {
        this.linker = linker;
        this.applicationCode = config.getString(Keys.OPTINEXUS_APPLICATION_CODE);
    }

    /**
     * Handles one webhook body.
     *
     * @return what was done: {@link #CREATED}, {@link #EXISTS} or {@link #IGNORED}
     * @throws IllegalArgumentException if the event is not valid (a refusal that retrying cannot fix)
     * @throws StorageException if the group could not be stored (worth a retry)
     */
    public String handle(String body) throws IOException, StorageException {
        JsonNode event = MAPPER.readTree(body);
        if (event == null || !event.isObject()) {
            throw new IllegalArgumentException("The event is not a JSON object");
        }
        if (!ASSIGNED.equals(event.path("event_type").asText())) {
            return IGNORED;
        }
        JsonNode payload = event.path("data").path("payload");
        if (!applicationCode.equals(payload.path("application_code").asText())) {
            return IGNORED;
        }
        String tenantId = event.path("tenant_id").asText("");
        try {
            tenantId = UUID.fromString(tenantId.trim()).toString();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("The event names no valid tenant");
        }
        return linker.ensureGroup(tenantId, payload.path("tenant_name").asText("")) ? CREATED : EXISTS;
    }

}
