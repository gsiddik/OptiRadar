package org.traccar.governance;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.traccar.api.BaseResource;
import org.traccar.api.resource.GovernanceResource;
import org.traccar.api.security.UserPrincipal;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.core.SecurityContext;
import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class GovernanceResourceProductsTest {

    private static final long USER = 7;
    private static final String TENANT = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";

    private GovernanceService governance;
    private HttpServletRequest request;
    private HttpSession session;
    private GovernedPrincipal principal;
    private GovernanceResource resource;

    private static void set(Object target, Class<?> type, String name, Object value) throws Exception {
        Field field = type.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    @BeforeEach
    public void setUp() throws Exception {
        governance = mock(GovernanceService.class);
        request = mock(HttpServletRequest.class);
        session = mock(HttpSession.class);
        when(request.getSession(false)).thenReturn(session);
        principal = GovernedPrincipal.central(USER, "5d3a7f9e-1b2c-4d5e-8f60-7a8b9c0d1e01", TENANT);
        when(governance.enabled()).thenReturn(true);
        when(governance.principal(USER)).thenReturn(principal);
        SecurityContext security = mock(SecurityContext.class);
        when(security.getUserPrincipal()).thenReturn(new UserPrincipal(USER, null));
        resource = new GovernanceResource();
        set(resource, GovernanceResource.class, "governance", governance);
        set(resource, GovernanceResource.class, "request", request);
        set(resource, BaseResource.class, "securityContext", security);
    }

    @Test
    public void withGovernanceOffTheSwitcherHasNothingToShowAndOptiNexusIsNotAsked() {
        when(governance.enabled()).thenReturn(false);

        Map<String, Object> body = resource.products(true);

        assertEquals(false, body.get("governed"));
        assertEquals(List.of(), body.get("products"));
        verify(governance, never()).products(any(), anyBoolean());
    }

    @Test
    public void theAnswerCarriesTheTenantAndTheProductsAndTheirValidity() {
        ProductContext.Tenant tenant = new ProductContext.Tenant(TENANT, "acme", "Acme");
        List<ProductContext.Product> products = List.of(
                new ProductContext.Product("optifleet", "OptiFleet", "https://fleet.example.test/?tenant_hint="
                        + TENANT, false));
        when(governance.products(principal, true)).thenReturn(new GovernanceService.Products(
                tenant, products, 1234L, 300));

        Map<String, Object> body = resource.products(true);

        assertEquals(true, body.get("governed"));
        assertEquals(tenant, body.get("tenant"));
        assertEquals(products, body.get("products"));
        assertEquals(300, body.get("ttlSeconds"));
        verify(session, never()).invalidate();
    }

    @Test
    public void whenTheAccessEndedTheBrowserSessionEndsAndTheRefusalIsRethrown() {
        when(governance.products(principal, true)).thenThrow(new GovernanceException(401,
                GovernanceException.ACCESS_REVOKED, "ended", null, 0, true));

        GovernanceException e = assertThrows(GovernanceException.class, () -> resource.products(true));

        assertEquals(401, e.getStatus());
        verify(session).invalidate();
    }

    @Test
    public void anOutageDoesNotEndTheBrowserSession() {
        when(governance.products(principal, false)).thenThrow(new GovernanceException(503,
                GovernanceException.UNAVAILABLE, "down", null, 5, false));

        GovernanceException e = assertThrows(GovernanceException.class, () -> resource.products(false));

        assertEquals(503, e.getStatus());
        assertFalse(e.endsSessions());
        verify(session, never()).invalidate();
    }

}
