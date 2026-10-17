package org.traccar.governance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.traccar.api.BaseResource;
import org.traccar.api.resource.AccessResource;
import org.traccar.api.security.UserPrincipal;
import org.traccar.helper.LogAction;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import java.lang.reflect.Field;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AccessResourceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long USER = 7;
    private static final String TARGET = "5d3a7f9e-1b2c-4d5e-8f60-7a8b9c0d1e09";

    private DelegationService delegation;
    private LogAction logAction;
    private AccessResource resource;

    private static void set(Object target, Class<?> type, String name, Object value) throws Exception {
        Field field = type.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    @BeforeEach
    public void setUp() throws Exception {
        delegation = mock(DelegationService.class);
        logAction = mock(LogAction.class);
        resource = new AccessResource();
        ContainerRequestContext context = mock(ContainerRequestContext.class);
        when(context.getHeaderString("X-Correlation-Id")).thenReturn("web-12345678");
        SecurityContext security = mock(SecurityContext.class);
        when(security.getUserPrincipal()).thenReturn(new UserPrincipal(USER, null));
        set(resource, AccessResource.class, "delegation", delegation);
        set(resource, AccessResource.class, "actionLogger", logAction);
        set(resource, AccessResource.class, "request", mock(HttpServletRequest.class));
        set(resource, AccessResource.class, "requestContext", context);
        set(resource, BaseResource.class, "securityContext", security);
    }

    @Test
    public void aSuccessIsAnsweredWithOptiNexusStatusAndDocumentAndAuditedAsOk() throws Exception {
        JsonNode data = MAPPER.readTree("{\"id\":\"x\"}");
        when(delegation.addUser(eq(USER), any())).thenReturn(new DelegationService.Result(201, data,
                MAPPER.missingNode()));

        Response response = resource.addUser(MAPPER.readTree("{\"email\":\"b@example.test\",\"name\":\"B\","
                + "\"initial_password\":\"correct horse battery\"}"));

        assertEquals(201, response.getStatus());
        assertEquals("no-store", response.getHeaderString("Cache-Control"));
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getEntity();
        assertEquals(data, body.get("data"));
        assertNull(body.get("meta"));
        verify(logAction).delegation(any(), eq(USER), eq("user.add"), eq("b@example.test"), eq("ok"),
                eq("web-12345678"));
    }

    @Test
    public void aRefusalIsAuditedWithItsCodeAndRethrownForTheMapper() {
        when(delegation.removeUser(USER, TARGET)).thenThrow(new DelegationException(409, "delegation_tenant_admin_"
                + "protected", "TENANT_ADMIN_PROTECTED", "no", null, 0));

        DelegationException e = assertThrows(DelegationException.class, () -> resource.removeUser(TARGET));

        assertEquals(409, e.getStatus());
        verify(logAction).delegation(any(), eq(USER), eq("user.remove"), eq(TARGET),
                eq("delegation_tenant_admin_protected"), eq("web-12345678"));
    }

    @Test
    public void thePasswordIsNeverPartOfTheAuditTrail() throws Exception {
        when(delegation.addUser(eq(USER), any())).thenReturn(new DelegationService.Result(200,
                MAPPER.readTree("{}"), MAPPER.missingNode()));

        resource.addUser(MAPPER.readTree("{\"email\":\"b@example.test\",\"name\":\"B\","
                + "\"initial_password\":\"correct horse battery\"}"));

        ArgumentCaptor<String> text = ArgumentCaptor.forClass(String.class);
        verify(logAction).delegation(any(), anyLong(), text.capture(), text.capture(), text.capture(),
                text.capture());
        for (String value : text.getAllValues()) {
            assertTrue(!value.contains("correct horse"), value);
        }
    }

    @Test
    public void readsAreNotAudited() {
        when(delegation.catalog(USER)).thenReturn(new DelegationService.Result(200, MAPPER.createObjectNode(),
                MAPPER.missingNode()));

        assertEquals(200, resource.catalog().getStatus());

        verify(logAction, never()).delegation(any(), anyLong(), any(), any(), any(), any());
    }

    @Test
    public void paginationMetaIsPassedOn() throws Exception {
        when(delegation.listUsers(USER, "bu", 10)).thenReturn(new DelegationService.Result(200,
                MAPPER.createArrayNode(), MAPPER.readTree("{\"pagination\":{\"total\":0}}")));

        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) resource.users("bu", 10).getEntity();

        assertTrue(body.containsKey("meta"));
    }

}
