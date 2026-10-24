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
package org.traccar.api.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.database.OpenIdTenantLinker;
import org.traccar.database.OptinexusEntitlements;
import org.traccar.storage.StorageException;

import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import java.security.Principal;
import java.util.Set;

/**
 * Refuses the features a tenant's plan does not include (only while optinexus.entitlements.enforce is on): every
 * report needs the OptiNexus capability "trip_reports", and changing geofences needs "geofences". A user linked to
 * several tenants is allowed when any of them has the feature; a user that belongs to no tenant is not limited.
 */
@Priority(Priorities.USER + 100)
public class FeatureEntitlementFilter implements ContainerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(FeatureEntitlementFilter.class);

    static final String REPORTS = "trip_reports";
    static final String GEOFENCES = "geofences";

    private final OptinexusEntitlements entitlements;
    private final OpenIdTenantLinker tenantLinker;

    @Inject
    public FeatureEntitlementFilter(OptinexusEntitlements entitlements, OpenIdTenantLinker tenantLinker) {
        this.entitlements = entitlements;
        this.tenantLinker = tenantLinker;
    }

    /**
     * The feature a request needs, or null when it needs none. The path is relative to the API root.
     */
    static String featureOf(String method, String path) {
        String first = path.startsWith("/") ? path.substring(1) : path;
        int slash = first.indexOf('/');
        String resource = slash < 0 ? first : first.substring(0, slash);
        if (resource.equals("reports")) {
            return REPORTS;
        }
        boolean read = method.equals("GET") || method.equals("HEAD") || method.equals("OPTIONS");
        if (resource.equals("geofences") && !read) {
            return GEOFENCES;
        }
        return null;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {
        if (!entitlements.enforced()) {
            return;
        }
        String feature = featureOf(requestContext.getMethod(), requestContext.getUriInfo().getPath());
        Principal principal = requestContext.getSecurityContext().getUserPrincipal();
        if (feature == null || !(principal instanceof UserPrincipal userPrincipal)) {
            return;
        }

        Set<String> tenants;
        try {
            tenants = tenantLinker.tenantsOf(userPrincipal.getUserId());
        } catch (StorageException e) {
            LOGGER.warn("Could not read the tenants of user {}", userPrincipal.getUserId(), e);
            throw new WebApplicationException(Response.status(Response.Status.SERVICE_UNAVAILABLE).build());
        }
        if (tenants.isEmpty() || tenants.stream().anyMatch(tenant -> entitlements.allows(tenant, feature))) {
            return;
        }
        throw new WebApplicationException("This feature is not included in your plan", Response.Status.FORBIDDEN);
    }

}
