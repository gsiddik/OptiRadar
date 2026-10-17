package org.traccar.governance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.traccar.api.security.UserPrincipal;

import jakarta.annotation.security.PermitAll;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.core.UriInfo;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class GovernanceRequestFilterTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String TENANT = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";
    private static final String SUBJECT = "5d3a7f9e-1b2c-4d5e-8f60-7a8b9c0d1e01";
    private static final long USER = 7;

    @Governed(read = Catalog.DEVICES_VIEW, write = Catalog.DEVICES_MANAGE)
    static class PairResource {
        public void list() { }

        public void create() { }

        @Governed(value = Catalog.DEVICES_ODOMETER_SET)
        public void odometer() { }

        @Governed(access = Governed.Access.OPERATOR)
        public void admin() { }

        @Governed(integration = true)
        public void onlyFlag() { }

        @PermitAll
        public void open() { }
    }

    @Governed(access = Governed.Access.SELF, selfOnly = true)
    static class SelfResource {
        public void get() { }
    }

    @Governed(access = Governed.Access.DYNAMIC, rule = "positions.get", integration = true)
    static class PositionsResource {
        public void get() { }

        @Governed(value = Catalog.POSITIONS_EXPORT)
        public void export() { }
    }

    @Governed(access = Governed.Access.DYNAMIC, rule = "permissions.link")
    static class LinkResource {
        public void add() { }
    }

    @Governed(read = Catalog.DEVICES_VIEW, integration = true)
    static class ReadOnlyIntegrationResource {
        public void list() { }
    }

    static class Unmapped {
        public void anything() { }
    }

    @Governed(access = Governed.Access.DYNAMIC, rule = "no.such.rule")
    static class UnknownRule {
        public void anything() { }
    }

    private GovernanceService governance;
    private ContainerRequestContext context;
    private ResourceInfo resourceInfo;
    private UriInfo uriInfo;
    private HttpServletRequest servletRequest;
    private MultivaluedMap<String, String> query;
    private MultivaluedMap<String, String> pathParameters;
    private GovernanceRequestFilter filter;

    @BeforeEach
    public void setUp() throws Exception {
        governance = mock(GovernanceService.class);
        when(governance.enabled()).thenReturn(true);
        context = mock(ContainerRequestContext.class);
        resourceInfo = mock(ResourceInfo.class);
        uriInfo = mock(UriInfo.class);
        servletRequest = mock(HttpServletRequest.class);
        query = new MultivaluedHashMap<>();
        pathParameters = new MultivaluedHashMap<>();
        when(uriInfo.getQueryParameters()).thenReturn(query);
        when(uriInfo.getPathParameters()).thenReturn(pathParameters);
        when(uriInfo.getPath()).thenReturn("devices");
        when(context.getUriInfo()).thenReturn(uriInfo);
        when(context.getMethod()).thenReturn("GET");
        SecurityContext security = mock(SecurityContext.class);
        when(security.getUserPrincipal()).thenReturn(new UserPrincipal(USER, null));
        when(context.getSecurityContext()).thenReturn(security);

        filter = new GovernanceRequestFilter();
        set("governance", governance);
        set("request", servletRequest);
        set("resourceInfo", resourceInfo);
    }

    private void set(String field, Object value) throws Exception {
        Field f = GovernanceRequestFilter.class.getDeclaredField(field);
        f.setAccessible(true);
        f.set(filter, value);
    }

    private void route(Class<?> type, String method, String verb) throws Exception {
        Method m = type.getMethod(method);
        when(resourceInfo.getResourceMethod()).thenReturn(m);
        when(resourceInfo.getResourceClass()).thenAnswer(invocation -> type);
        when(context.getMethod()).thenReturn(verb);
    }

    private void as(GovernedPrincipal principal) {
        when(governance.principal(USER)).thenReturn(principal);
    }

    private GovernedPrincipal tenantUser() {
        return GovernedPrincipal.central(USER, SUBJECT, TENANT);
    }

    private void body(String json) throws IOException {
        when(context.getEntityStream()).thenReturn(new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)));
    }

    private Response aborted() {
        ArgumentCaptor<Response> captor = ArgumentCaptor.forClass(Response.class);
        verify(context).abortWith(captor.capture());
        return captor.getValue();
    }

    private JsonNode json(Response response) throws Exception {
        return MAPPER.readTree((String) response.getEntity());
    }

    // ---------------------------------------------------------------------------------------------------------
    // What a route needs

    @Test
    public void classDefaultsFollowTheHttpVerb() throws Exception {
        Method list = PairResource.class.getMethod("list");

        assertEquals(List.of(Catalog.DEVICES_VIEW),
                GovernanceRequestFilter.requirement(list, PairResource.class, "GET").permissions());
        assertEquals(List.of(Catalog.DEVICES_VIEW),
                GovernanceRequestFilter.requirement(list, PairResource.class, "HEAD").permissions());
        for (String verb : List.of("POST", "PUT", "DELETE", "PATCH")) {
            assertEquals(List.of(Catalog.DEVICES_MANAGE),
                    GovernanceRequestFilter.requirement(list, PairResource.class, verb).permissions(), verb);
        }
    }

    @Test
    public void methodAnnotationBeatsTheClassDefaultWhateverTheVerb() throws Exception {
        Method method = PairResource.class.getMethod("odometer");

        assertEquals(List.of(Catalog.DEVICES_ODOMETER_SET),
                GovernanceRequestFilter.requirement(method, PairResource.class, "PUT").permissions());
        assertEquals(List.of(Catalog.DEVICES_ODOMETER_SET),
                GovernanceRequestFilter.requirement(method, PairResource.class, "GET").permissions());
        assertEquals(Governed.Access.OPERATOR, GovernanceRequestFilter.requirement(
                PairResource.class.getMethod("admin"), PairResource.class, "GET").access());
    }

    @Test
    public void aMethodThatOnlySetsTheIntegrationFlagStillUsesTheClassDefault() throws Exception {
        Method method = PairResource.class.getMethod("onlyFlag");

        GovernanceRequestFilter.Requirement requirement =
                GovernanceRequestFilter.requirement(method, PairResource.class, "GET");

        assertEquals(List.of(Catalog.DEVICES_VIEW), requirement.permissions());
        assertTrue(requirement.integration());
    }

    @Test
    public void aMethodLevelOverrideDoesNotInheritTheClassIntegrationFlag() throws Exception {
        Method export = PositionsResource.class.getMethod("export");
        Method get = PositionsResource.class.getMethod("get");

        assertTrue(!GovernanceRequestFilter.requirement(export, PositionsResource.class, "GET").integration());
        assertTrue(GovernanceRequestFilter.requirement(get, PositionsResource.class, "GET").integration());
    }

    @Test
    public void aRouteWithoutAnAnswerHasNoRequirement() throws Exception {
        assertNull(GovernanceRequestFilter.requirement(Unmapped.class.getMethod("anything"), Unmapped.class, "GET"));
    }

    // ---------------------------------------------------------------------------------------------------------
    // Filter

    @Test
    public void nothingHappensWhileGovernanceIsOff() throws Exception {
        when(governance.enabled()).thenReturn(false);
        route(PairResource.class, "list", "GET");

        filter.filter(context);

        verify(governance, never()).principal(anyLong());
        verify(context, never()).abortWith(any());
    }

    @Test
    public void preflightPermitAllAndAnonymousRequestsAreNotDecidedHere() throws Exception {
        route(PairResource.class, "list", "OPTIONS");
        filter.filter(context);
        route(PairResource.class, "open", "GET");
        filter.filter(context);
        route(PairResource.class, "list", "GET");
        SecurityContext anonymous = mock(SecurityContext.class);
        when(context.getSecurityContext()).thenReturn(anonymous);
        filter.filter(context);

        verify(governance, never()).principal(anyLong());
        verify(context, never()).abortWith(any());
    }

    @Test
    public void operatorPassesWithoutAnyGrant() throws Exception {
        route(PairResource.class, "create", "POST");
        as(GovernedPrincipal.operator(USER));

        filter.filter(context);

        verify(governance, never()).require(any(), anyCollection());
        verify(context, never()).abortWith(any());
    }

    @Test
    public void tenantUserNeedsTheRoutePermissionFromOptiNexus() throws Exception {
        route(PairResource.class, "create", "POST");
        as(tenantUser());

        filter.filter(context);

        verify(governance).require(tenantUser(), List.of(Catalog.DEVICES_MANAGE));
        verify(context, never()).abortWith(any());
    }

    @Test
    public void aRefusalAbortsWithStableJsonAndACorrelationId() throws Exception {
        route(PairResource.class, "create", "POST");
        as(tenantUser());
        doThrow(new GovernanceException(403, GovernanceException.PERMISSION_DENIED, "internal detail",
                Catalog.DEVICES_MANAGE)).when(governance).require(any(), anyCollection());

        filter.filter(context);

        Response response = aborted();
        assertEquals(403, response.getStatus());
        assertEquals("no-store", response.getHeaderString("Cache-Control"));
        JsonNode body = json(response);
        assertEquals(GovernanceException.PERMISSION_DENIED, body.path("error").asText());
        assertEquals(Catalog.DEVICES_MANAGE, body.path("permission").asText());
        assertTrue(body.path("correlationId").asText().length() >= 8);
        assertEquals(body.path("correlationId").asText(), response.getHeaderString("X-Correlation-Id"));
        assertTrue(!response.getEntity().toString().contains("internal detail"), "no internal detail leaks");
        verify(governance, never()).endSessions(anyLong());
    }

    @Test
    public void aWellFormedCorrelationIdFromTheCallerIsKeptAndABadOneIsReplaced() throws Exception {
        route(PairResource.class, "create", "POST");
        as(GovernedPrincipal.denied(USER, GovernanceException.IDENTITY_REQUIRED));
        when(context.getHeaderString("X-Correlation-Id")).thenReturn("web-1234.abcd");
        filter.filter(context);
        assertEquals("web-1234.abcd", aborted().getHeaderString("X-Correlation-Id"));

        ContainerRequestContext second = mock(ContainerRequestContext.class);
        when(second.getHeaderString("X-Correlation-Id")).thenReturn("bad id <script>");
        assertTrue(GovernanceRequestFilter.correlationId(second).matches("^[a-f0-9]{16}$"));
    }

    @Test
    public void outageAnswers503WithRetryAfterAndKeepsTheSession() throws Exception {
        route(PairResource.class, "list", "GET");
        as(tenantUser());
        doThrow(new GovernanceException(503, GovernanceException.UNAVAILABLE, "down", null, 17, false))
                .when(governance).require(any(), anyCollection());

        filter.filter(context);

        Response response = aborted();
        assertEquals(503, response.getStatus());
        assertEquals("17", response.getHeaderString("Retry-After"));
        assertEquals(GovernanceException.UNAVAILABLE, json(response).path("error").asText());
        verify(governance, never()).endSessions(anyLong());
        verify(servletRequest, never()).getSession(false);
    }

    @Test
    public void accessEndedAtOptiNexusEndsTheSessionsAnd401() throws Exception {
        route(PairResource.class, "list", "GET");
        as(tenantUser());
        HttpSession session = mock(HttpSession.class);
        when(servletRequest.getSession(false)).thenReturn(session);
        doThrow(new GovernanceException(401, GovernanceException.ACCESS_REVOKED, "ended", null, 0, true))
                .when(governance).require(any(), anyCollection());

        filter.filter(context);

        assertEquals(401, aborted().getStatus());
        verify(governance).endSessions(USER);
        verify(session).invalidate();
    }

    @Test
    public void aCallWithoutABrowserSessionStillGetsItsAnswer() throws Exception {
        route(PairResource.class, "list", "GET");
        as(tenantUser());
        when(servletRequest.getSession(false)).thenThrow(new IllegalStateException("no request"));
        doThrow(new GovernanceException(401, GovernanceException.ACCESS_REVOKED, "ended", null, 0, true))
                .when(governance).require(any(), anyCollection());

        filter.filter(context);

        assertEquals(401, aborted().getStatus());
    }

    @Test
    public void unmappedRoutesAreRefusedForTenantUsers() throws Exception {
        route(Unmapped.class, "anything", "GET");
        as(tenantUser());

        filter.filter(context);

        Response response = aborted();
        assertEquals(403, response.getStatus());
        assertEquals(GovernanceException.ROUTE_UNMAPPED, json(response).path("error").asText());
        verify(governance, never()).require(any(), anyCollection());
    }

    @Test
    public void unmappedRoutesStayOpenToOperators() throws Exception {
        route(Unmapped.class, "anything", "GET");
        as(GovernedPrincipal.operator(USER));

        filter.filter(context);

        verify(context, never()).abortWith(any());
    }

    @Test
    public void operatorOnlyRoutesRefuseTenantUsers() throws Exception {
        route(PairResource.class, "admin", "GET");
        as(tenantUser());

        filter.filter(context);

        assertEquals(GovernanceException.OPERATOR_ONLY, json(aborted()).path("error").asText());
    }

    @Test
    public void deniedAccountsAreRefusedEverywhereWithTheirCode() throws Exception {
        route(PairResource.class, "list", "GET");
        as(GovernedPrincipal.denied(USER, GovernanceException.TENANT_UNRESOLVED));

        filter.filter(context);

        Response response = aborted();
        assertEquals(403, response.getStatus());
        assertEquals(GovernanceException.TENANT_UNRESOLVED, json(response).path("error").asText());
    }

    @Test
    public void selfRoutesNeedOnlyASignedInAccountAndSelfOnlyChecksTheId() throws Exception {
        route(SelfResource.class, "get", "GET");
        as(tenantUser());
        pathParameters.add("id", String.valueOf(USER));

        filter.filter(context);

        verify(governance).requireSignedIn(tenantUser());
        verify(context, never()).abortWith(any());

        pathParameters.clear();
        pathParameters.add("id", "99");
        filter.filter(context);

        assertEquals(GovernanceException.OPERATOR_ONLY, json(aborted()).path("error").asText());
    }

    @Test
    public void integrationAccountsMayOnlyReadWhatIsMarkedForThem() throws Exception {
        as(GovernedPrincipal.integration(USER));

        route(ReadOnlyIntegrationResource.class, "list", "GET");
        filter.filter(context);
        verify(context, never()).abortWith(any());

        route(PairResource.class, "list", "GET");
        filter.filter(context);
        assertEquals(403, aborted().getStatus());
    }

    @Test
    public void integrationAccountsNeverWrite() throws Exception {
        as(GovernedPrincipal.integration(USER));
        route(ReadOnlyIntegrationResource.class, "list", "POST");

        filter.filter(context);

        assertEquals(403, aborted().getStatus());
    }

    // ---------------------------------------------------------------------------------------------------------
    // Rules that depend on the request

    @Test
    public void positionsNeedLiveViewForTheLatestAndHistoryForARange() throws Exception {
        route(PositionsResource.class, "get", "GET");
        as(tenantUser());

        filter.filter(context);
        verify(governance).require(tenantUser(), List.of(Catalog.LIVE_VIEW));

        query.add("deviceId", "1");
        query.add("from", "2026-01-01T00:00:00Z");
        filter.filter(context);
        verify(governance).require(tenantUser(), List.of(Catalog.POSITIONS_VIEW));
    }

    @Test
    public void positionsByIdAreHistory() throws Exception {
        route(PositionsResource.class, "get", "GET");
        as(tenantUser());
        query.add("id", "55");

        filter.filter(context);

        verify(governance).require(tenantUser(), List.of(Catalog.POSITIONS_VIEW));
    }

    @Test
    public void exportsNeedTheirOwnPermission() throws Exception {
        route(PositionsResource.class, "export", "GET");
        as(tenantUser());

        filter.filter(context);

        verify(governance).require(tenantUser(), List.of(Catalog.POSITIONS_EXPORT));
    }

    @Test
    public void anUnknownRuleIsRefused() throws Exception {
        route(UnknownRule.class, "anything", "GET");
        as(tenantUser());

        filter.filter(context);

        assertEquals(GovernanceException.ROUTE_UNMAPPED, json(aborted()).path("error").asText());
    }

    @SuppressWarnings("unchecked")
    private List<String> linkRequires(String json) throws Exception {
        route(LinkResource.class, "add", "POST");
        as(tenantUser());
        body(json);
        filter.filter(context);
        ArgumentCaptor<Collection<String>> captor = ArgumentCaptor.forClass(Collection.class);
        verify(governance).require(eq(tenantUser()), captor.capture());
        return List.copyOf(captor.getValue());
    }

    @Test
    public void linkingADeviceToAGeofenceNeedsToManageGeofences() throws Exception {
        assertEquals(List.of(Catalog.GEOFENCES_MANAGE), linkRequires("{\"deviceId\":1,\"geofenceId\":2}"));
    }

    @Test
    public void linkingAGroupToAGeofenceNeedsToManageGeofences() throws Exception {
        assertEquals(List.of(Catalog.GEOFENCES_MANAGE), linkRequires("{\"groupId\":1,\"geofenceId\":2}"));
    }

    @Test
    public void linkingANotificationToACommandNeedsToSendCommandsToo() throws Exception {
        List<String> required = linkRequires("{\"notificationId\":4,\"commandId\":9}");

        assertTrue(required.contains(Catalog.NOTIFICATIONS_MANAGE));
        assertTrue(required.contains(Catalog.COMMANDS_MANAGE));
        assertTrue(required.contains(Catalog.COMMANDS_SEND), "a notification that sends a command is sending it");
    }

    @Test
    public void aUserMaySubscribeThemselvesToANotificationOrReport() throws Exception {
        assertEquals(List.of(Catalog.NOTIFICATIONS_MANAGE),
                linkRequires("{\"userId\":" + USER + ",\"notificationId\":4}"));
    }

    @Test
    public void linkingAnotherUserIsForAdministratorsOnly() throws Exception {
        route(LinkResource.class, "add", "POST");
        as(tenantUser());
        body("{\"userId\":8,\"notificationId\":4}");

        filter.filter(context);

        assertEquals(GovernanceException.OPERATOR_ONLY, json(aborted()).path("error").asText());
    }

    @Test
    public void userToDeviceOrGroupLinksAreForAdministratorsOnly() throws Exception {
        for (String link : List.of("{\"userId\":" + USER + ",\"deviceId\":1}", "{\"userId\":" + USER
                + ",\"groupId\":1}", "{\"userId\":1,\"managedUserId\":2}")) {
            setUp();
            route(LinkResource.class, "add", "POST");
            as(tenantUser());
            body(link);

            filter.filter(context);

            assertEquals(GovernanceException.OPERATOR_ONLY, json(aborted()).path("error").asText(), link);
        }
    }

    @Test
    public void deviceToGroupLinkNeedsToManageGroups() throws Exception {
        assertEquals(List.of(Catalog.GROUPS_MANAGE), linkRequires("{\"deviceId\":1,\"groupId\":2}"));
    }

    @Test
    public void unknownMalformedOrOversizedLinksAreRefused() throws Exception {
        for (String link : List.of("{\"deviceId\":1,\"somethingId\":2}", "{\"deviceId\":1}",
                "{\"deviceId\":1,\"geofenceId\":2,\"groupId\":3}", "[]", "{", "")) {
            setUp();
            route(LinkResource.class, "add", "POST");
            as(tenantUser());
            body(link);

            filter.filter(context);

            assertEquals(403, aborted().getStatus(), link);
            verify(governance, never()).require(any(), anyCollection());
        }
    }

    @Test
    public void oversizedLinkBodiesAreRefusedWithoutBeingParsed() throws Exception {
        route(LinkResource.class, "add", "POST");
        as(tenantUser());
        when(context.getEntityStream()).thenReturn(new InputStream() {
            @Override
            public int read() {
                return ' ';
            }
        });

        filter.filter(context);

        assertEquals(403, aborted().getStatus());
    }

    @Test
    public void everyEntryOfABatchIsChecked() throws Exception {
        List<String> required = linkRequires("[{\"deviceId\":1,\"geofenceId\":2},{\"deviceId\":1,\"driverId\":3}]");

        assertTrue(required.contains(Catalog.GEOFENCES_MANAGE));
        assertTrue(required.contains(Catalog.DRIVERS_MANAGE));
    }

    @Test
    public void theBodyIsStillReadableByTheResourceAfterTheCheck() throws Exception {
        linkRequires("{\"deviceId\":1,\"geofenceId\":2}");

        ArgumentCaptor<InputStream> captor = ArgumentCaptor.forClass(InputStream.class);
        verify(context).setEntityStream(captor.capture());
        assertNotNull(captor.getValue());
        assertEquals("{\"deviceId\":1,\"geofenceId\":2}",
                new String(captor.getValue().readAllBytes(), StandardCharsets.UTF_8));
    }

    @Test
    public void exceptionMapperUsesTheSameShape() throws Exception {
        Response response = new GovernanceExceptionMapper().toResponse(
                new GovernanceException(403, GovernanceException.NOT_ENTITLED, "x", Catalog.LIVE_VIEW));

        assertEquals(403, response.getStatus());
        assertEquals(GovernanceException.NOT_ENTITLED, MAPPER.readTree((String) response.getEntity())
                .path("error").asText());
    }

}
