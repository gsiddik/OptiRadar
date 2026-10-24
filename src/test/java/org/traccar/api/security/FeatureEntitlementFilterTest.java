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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.traccar.database.OpenIdTenantLinker;
import org.traccar.database.OptinexusEntitlements;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.core.UriInfo;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class FeatureEntitlementFilterTest {

    private static final String TENANT_A = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";
    private static final String TENANT_B = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c02";
    private static final long USER = 7;

    private OptinexusEntitlements entitlements;
    private OpenIdTenantLinker linker;
    private FeatureEntitlementFilter filter;

    @BeforeEach
    public void setUp() {
        entitlements = mock(OptinexusEntitlements.class);
        linker = mock(OpenIdTenantLinker.class);
        when(entitlements.enforced()).thenReturn(true);
        filter = new FeatureEntitlementFilter(entitlements, linker);
    }

    private ContainerRequestContext request(String method, String path, Long userId) {
        ContainerRequestContext context = mock(ContainerRequestContext.class);
        UriInfo uriInfo = mock(UriInfo.class);
        SecurityContext securityContext = mock(SecurityContext.class);
        when(context.getMethod()).thenReturn(method);
        when(context.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getPath()).thenReturn(path);
        when(context.getSecurityContext()).thenReturn(securityContext);
        when(securityContext.getUserPrincipal()).thenReturn(userId == null ? null : new UserPrincipal(userId, null));
        return context;
    }

    @Test
    public void mapsReportsAndGeofenceChangesToFeatures() {
        assertEquals("trip_reports", FeatureEntitlementFilter.featureOf("GET", "reports/trips"));
        assertEquals("trip_reports", FeatureEntitlementFilter.featureOf("POST", "/reports/summary"));
        assertEquals("geofences", FeatureEntitlementFilter.featureOf("POST", "geofences"));
        assertEquals("geofences", FeatureEntitlementFilter.featureOf("DELETE", "geofences/4"));
        assertNull(FeatureEntitlementFilter.featureOf("GET", "geofences"));
        assertNull(FeatureEntitlementFilter.featureOf("GET", "devices"));
        assertNull(FeatureEntitlementFilter.featureOf("POST", "devices"));
        assertNull(FeatureEntitlementFilter.featureOf("GET", "reportsfoo/x"));
    }

    @Test
    public void doesNothingWhileEnforcementIsOff() throws Exception {
        when(entitlements.enforced()).thenReturn(false);

        filter.filter(request("GET", "reports/trips", USER));

        verify(linker, never()).tenantsOf(USER);
    }

    @Test
    public void refusesAFeatureTheTenantDoesNotHave() throws Exception {
        when(linker.tenantsOf(USER)).thenReturn(Set.of(TENANT_A));
        when(entitlements.allows(TENANT_A, "trip_reports")).thenReturn(false);

        WebApplicationException e = assertThrows(WebApplicationException.class,
                () -> filter.filter(request("GET", "reports/trips", USER)));

        assertEquals(403, e.getResponse().getStatus());
    }

    @Test
    public void allowsAFeatureTheTenantHas() throws Exception {
        when(linker.tenantsOf(USER)).thenReturn(Set.of(TENANT_A));
        when(entitlements.allows(TENANT_A, "geofences")).thenReturn(true);

        filter.filter(request("POST", "geofences", USER));
    }

    @Test
    public void aUserOfSeveralTenantsNeedsOnlyOneToHaveTheFeature() throws Exception {
        when(linker.tenantsOf(USER)).thenReturn(Set.of(TENANT_A, TENANT_B));
        when(entitlements.allows(TENANT_A, "trip_reports")).thenReturn(false);
        when(entitlements.allows(TENANT_B, "trip_reports")).thenReturn(true);

        filter.filter(request("GET", "reports/trips", USER));
    }

    @Test
    public void aUserWithoutATenantIsNotLimited() throws Exception {
        when(linker.tenantsOf(USER)).thenReturn(Set.of());

        filter.filter(request("GET", "reports/trips", USER));

        verify(entitlements, never()).allows(TENANT_A, "trip_reports");
    }

    @Test
    public void leavesOtherRequestsAndAnonymousOnesAlone() throws Exception {
        filter.filter(request("GET", "devices", USER));
        filter.filter(request("GET", "reports/trips", null));

        verify(linker, never()).tenantsOf(USER);
    }

}
