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
import org.traccar.database.EmbedSessionIssuer;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.util.Map;

/**
 * Called by OptiNexus (with an administrator's API token) to open an embed session for one tenant: a read-only token
 * of at most 15 minutes that sees that tenant's devices and nothing else.
 */
@Path("optinexus/embed")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
public class EmbedResource extends BaseResource {

    @Inject
    private EmbedSessionIssuer issuer;

    @POST
    public Map<String, Object> open(
            @FormParam("tenantId") String tenantId,
            @FormParam("ttl") Long ttl) throws Exception {
        permissionsService.checkAdmin(getUserId());
        long seconds = ttl != null ? ttl : EmbedSessionIssuer.MAX_TTL_SECONDS;
        EmbedSessionIssuer.Session session = issuer.issue(tenantId, seconds);
        return Map.of("token", session.token(), "expiresAt", session.expiration());
    }

}
