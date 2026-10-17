package org.traccar.telematics;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.traccar.api.BaseResource;
import org.traccar.api.resource.TelematicsResource;
import org.traccar.api.security.UserPrincipal;
import org.traccar.governance.Catalog;
import org.traccar.governance.Governed;

import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.SecurityContext;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class TelematicsResourceTest {

    private static final long USER = 7;
    private static final String TENANT = "0B1F6C1E-6A3A-4C5E-9D52-6F0F6A1B2C01";

    private TelematicsSnapshot snapshot;
    private TelematicsResource resource;

    private static void set(Object target, Class<?> type, String name, Object value) throws Exception {
        Field field = type.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    @BeforeEach
    public void setUp() throws Exception {
        snapshot = mock(TelematicsSnapshot.class);
        when(snapshot.latest(eq(USER), any())).thenReturn(Map.of("items", List.of()));
        SecurityContext security = mock(SecurityContext.class);
        when(security.getUserPrincipal()).thenReturn(new UserPrincipal(USER, null));
        resource = new TelematicsResource();
        set(resource, TelematicsResource.class, "snapshot", snapshot);
        set(resource, BaseResource.class, "securityContext", security);
    }

    private TelematicsSnapshot.Query query() throws Exception {
        ArgumentCaptor<TelematicsSnapshot.Query> captor = ArgumentCaptor.forClass(TelematicsSnapshot.Query.class);
        verify(snapshot).latest(eq(USER), captor.capture());
        return captor.getValue();
    }

    @Test
    public void theCallerIsTheAuthenticatedUserAndNothingFromTheRequestNamesATenantToTrust() throws Exception {
        resource.latest(0, 500, null, null);

        TelematicsSnapshot.Query query = query();
        assertEquals(0, query.after());
        assertEquals(500, query.limit());
        assertFalse(query.includeLocation());
        assertNull(query.tenantId());
    }

    @Test
    public void locationIsOptInAndTheTenantFilterIsNormalised() throws Exception {
        resource.latest(12, 50, " Location ", " " + TENANT + " ");

        TelematicsSnapshot.Query query = query();
        assertTrue(query.includeLocation());
        assertEquals(TENANT.toLowerCase(), query.tenantId());
        assertEquals(12, query.after());
    }

    @Test
    public void badParametersAreRefusedBeforeAnythingIsRead() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> resource.latest(0, 500, "everything", null));
        assertThrows(IllegalArgumentException.class, () -> resource.latest(0, 500, null, "acme"));
        assertThrows(IllegalArgumentException.class, () -> resource.latest(0, 500, null, "x' OR '1'='1"));
        assertThrows(IllegalArgumentException.class, () -> resource.latest(-1, 500, null, null));
        assertThrows(IllegalArgumentException.class, () -> resource.latest(0, 0, null, null));
        assertThrows(IllegalArgumentException.class, () -> resource.latest(0, 1001, null, null));
        verify(snapshot, never()).latest(eq(USER), any());
    }

    @Test
    public void theRouteIsVersionedReadOnlyAndGovernedAsLiveViewForTenantsAndIntegrationReaders() throws Exception {
        Method method = TelematicsResource.class.getMethod("latest", long.class, int.class, String.class,
                String.class);

        assertEquals("v1/latest", method.getAnnotation(Path.class).value());
        assertTrue(method.isAnnotationPresent(GET.class));
        Governed governed = TelematicsResource.class.getAnnotation(Governed.class);
        assertEquals(Catalog.LIVE_VIEW, governed.value());
        assertTrue(governed.integration());
        assertEquals("telematics", TelematicsResource.class.getAnnotation(Path.class).value());
        long writes = Arrays.stream(TelematicsResource.class.getDeclaredMethods())
                .filter(m -> m.isAnnotationPresent(POST.class)
                        || m.isAnnotationPresent(PUT.class)
                        || m.isAnnotationPresent(DELETE.class)).count();
        assertEquals(0, writes);
    }

}
