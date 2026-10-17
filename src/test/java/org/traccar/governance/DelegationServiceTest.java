package org.traccar.governance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.model.User;

import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DelegationServiceTest extends GovernanceTestBase {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String ROLE = "9f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e01";
    private static final String TARGET = "5d3a7f9e-1b2c-4d5e-8f60-7a8b9c0d1e09";
    private static final String BASE = "/api/v1/delegation/tenants/" + TENANT_A;

    private DelegationService delegation;
    private User admin;
    private volatile FakeNexus.Reply reply;

    @BeforeEach
    public void setUp() throws Exception {
        reply = null;
        permissionsBody = grants(SUBJECT_1, TENANT_A, true, null, 300, Catalog.LIVE_VIEW, Catalog.ACCESS_MANAGE);
        FakeNexus.Handler handler = call -> reply != null ? reply : FakeNexus.Reply.ok("{}");
        for (String method : List.of("GET", "POST", "PUT", "DELETE")) {
            nexus.route(method, "/api/v1/delegation/", DelegationService.SCOPE, handler);
        }
        delegation = new DelegationService(service(), nexusClient);
        admin = addTenantUser("admin", SUBJECT_1, groupA);
    }

    private static JsonNode json(String text) {
        try {
            return MAPPER.readTree(text);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private FakeNexus.Call last() {
        List<FakeNexus.Call> calls = nexus.calls("/api/v1/delegation/");
        return calls.get(calls.size() - 1);
    }

    private static DelegationException refusedCall(Runnable action) {
        return assertThrows(DelegationException.class, action::run);
    }

    private int delegationCalls() {
        return nexus.calls("/api/v1/delegation/").size();
    }

    // ---------------------------------------------------------------------------------------------------------
    // Who is acting

    @Test
    public void tenantAndActingUserComeFromTheIdentityLink() {
        reply = FakeNexus.Reply.ok("{\"delegable_permissions\":[],\"roles\":[]}");

        delegation.catalog(admin.getId());

        FakeNexus.Call call = last();
        assertEquals("GET", call.method());
        assertEquals(BASE + "/catalog", call.path());
        assertEquals("acting_user_id=" + SUBJECT_1, call.query());
        assertEquals(DelegationService.SCOPE, call.scope());
    }

    @Test
    public void aRequestCannotNameTheTenantOrTheActorItself() {
        for (String field : List.of("tenant_id", "acting_user_id", "actingUserId", "tenantId")) {
            JsonNode body = json("{\"email\":\"a@b.test\",\"name\":\"A\",\"" + field + "\":\"" + TENANT_B + "\"}");

            DelegationException e = refusedCall(() -> delegation.addUser(admin.getId(), body));

            assertEquals(422, e.getStatus(), field);
            assertEquals(DelegationException.INVALID_REQUEST, e.getCode(), field);
        }
        assertEquals(0, delegationCalls());
    }

    @Test
    public void localAdministratorsAndPasswordUsersHaveNoOptiNexusIdentityToActAs() throws Exception {
        User operator = addUser("root", true, false);
        User local = addUser("local", false, false);

        assertEquals(DelegationException.ACTOR_REQUIRED,
                refusedCall(() -> delegation.catalog(operator.getId())).getCode());
        assertEquals(403, refusedCall(() -> delegation.catalog(local.getId())).getStatus());
        assertEquals(0, delegationCalls());
    }

    @Test
    public void offWhenGovernanceIsOff() {
        Config config = config();
        config.setString(Keys.GOVERNANCE_ENABLE, "false");
        DelegationService off = new DelegationService(service(config), nexusClient);

        DelegationException e = refusedCall(() -> off.catalog(admin.getId()));

        assertEquals(404, e.getStatus());
        assertEquals(DelegationException.DISABLED, e.getCode());
        assertEquals(0, delegationCalls());
    }

    // ---------------------------------------------------------------------------------------------------------
    // Operations

    @Test
    public void usersListIsPagedSearchedAndEncoded() {
        reply = new FakeNexus.Reply(200, "{\"success\":true,\"data\":[{\"id\":\"" + TARGET + "\",\"name\":\"Budi\","
                + "\"roles\":[]}],\"meta\":{\"pagination\":{\"current_page\":1,\"per_page\":25,\"total\":1,"
                + "\"last_page\":1}}}", Map.of());

        DelegationService.Result result = delegation.listUsers(admin.getId(), "bu di&x=1 {a}", 500);

        FakeNexus.Call call = last();
        assertEquals(BASE + "/users", call.path());
        assertTrue(call.query().contains("per_page=100"), "clamped: " + call.query());
        assertTrue(call.query().endsWith("&acting_user_id=" + SUBJECT_1));
        String search = URLDecoder.decode(call.query().split("search=")[1].split("&per_page")[0],
                StandardCharsets.UTF_8);
        assertEquals("bu di&x=1 {a}", search, "the search text cannot add parameters");
        assertEquals(1, result.data().size());
        assertEquals(1, result.meta().path("pagination").path("total").asInt());
    }

    @Test
    public void addUserForwardsOnlyTheKnownFieldsAndTheActor() {
        reply = FakeNexus.Reply.created("{\"outcome\":\"created\",\"id\":\"" + TARGET + "\",\"roles\":[]}");

        DelegationService.Result result = delegation.addUser(admin.getId(), json(
                "{\"email\":\"  budi@example.test \",\"name\":\"Budi\",\"initial_password\":\"correct horse battery\","
                        + "\"role_ids\":[\"" + ROLE.toUpperCase() + "\"]}"));

        assertEquals(201, result.status());
        FakeNexus.Call call = last();
        assertEquals("POST", call.method());
        assertEquals(BASE + "/users", call.path());
        JsonNode sent = json(call.body());
        assertEquals("budi@example.test", sent.path("email").asText());
        assertEquals(SUBJECT_1, sent.path("acting_user_id").asText());
        assertEquals(ROLE, sent.path("role_ids").get(0).asText());
        assertEquals(5, sent.size());
    }

    @Test
    public void addUserChecksEmailNameAndPasswordShapeBeforeCalling() {
        JsonNode body = json("{\"email\":\"nope\",\"initial_password\":\"short\",\"role_ids\":[\"not-a-uuid\"]}");

        DelegationException e = refusedCall(() -> delegation.addUser(admin.getId(), body));

        assertEquals(422, e.getStatus());
        JsonNode details = e.getDetails();
        assertEquals("invalid", details.path("email").asText());
        assertEquals("required", details.path("name").asText());
        assertEquals("too short", details.path("initial_password").asText());
        assertTrue(details.has("role_ids"));
        assertEquals(0, delegationCalls());
    }

    @Test
    public void thePasswordNeverComesBack() {
        reply = FakeNexus.Reply.ok("{\"outcome\":\"linked\",\"id\":\"" + TARGET + "\"}");

        DelegationService.Result result = delegation.addUser(admin.getId(), json(
                "{\"email\":\"b@example.test\",\"name\":\"B\",\"initial_password\":\"correct horse battery\"}"));

        assertEquals(200, result.status());
        assertFalse(result.data().toString().contains("correct horse"));
    }

    @Test
    public void setRolesReplacesTheListAndRefreshesThatUsersGrants() throws Exception {
        reply = FakeNexus.Reply.ok("{\"id\":\"" + TARGET + "\",\"roles\":[]}");
        User target = addTenantUser("budi", TARGET, groupA);
        permissionsBody = grants(TARGET, TENANT_A, true, null, 300, Catalog.LIVE_VIEW);
        GovernanceService governance = service();
        delegation = new DelegationService(governance, nexusClient);
        governance.require(governance.principal(target.getId()), List.of(Catalog.LIVE_VIEW));
        int before = nexus.calls("/api/v1/authorization/effective-permissions").size();

        delegation.setUserRoles(admin.getId(), TARGET.toUpperCase(), json("{\"role_ids\":[\"" + ROLE + "\"]}"));

        FakeNexus.Call call = last();
        assertEquals("PUT", call.method());
        assertEquals(BASE + "/users/" + TARGET + "/roles", call.path());
        assertEquals(SUBJECT_1, json(call.body()).path("acting_user_id").asText());
        governance.require(governance.principal(target.getId()), List.of(Catalog.LIVE_VIEW));
        assertEquals(before + 1, nexus.calls("/api/v1/authorization/effective-permissions").size(),
                "the changed user's grants are asked again at once");
    }

    @Test
    public void setRolesNeedsTheListEvenWhenEmpty() {
        DelegationException e = refusedCall(() -> delegation.setUserRoles(admin.getId(), TARGET, json("{}")));
        assertEquals("required", e.getDetails().path("role_ids").asText());

        reply = FakeNexus.Reply.ok("{}");
        delegation.setUserRoles(admin.getId(), TARGET, json("{\"role_ids\":[]}"));
        assertEquals("[]", json(last().body()).path("role_ids").toString());
    }

    @Test
    public void idsInThePathMustBeUuidsSoTheyCannotReshapeTheUrl() {
        for (String bad : List.of("../../oauth/token", "x", TARGET + "/roles", "a b", "")) {
            assertEquals(422, refusedCall(() -> delegation.removeUser(admin.getId(), bad)).getStatus(), bad);
            assertEquals(422, refusedCall(() -> delegation.deleteRole(admin.getId(), bad)).getStatus(), bad);
        }
        assertEquals(0, delegationCalls());
    }

    @Test
    public void removeUserIsADeleteWithTheActorInTheQuery() {
        reply = FakeNexus.Reply.ok("null");

        delegation.removeUser(admin.getId(), TARGET);

        FakeNexus.Call call = last();
        assertEquals("DELETE", call.method());
        assertEquals(BASE + "/users/" + TARGET, call.path());
        assertEquals("acting_user_id=" + SUBJECT_1, call.query());
        assertEquals("", call.body());
    }

    @Test
    public void createRoleValidatesAndForwardsPermissionKeys() {
        reply = FakeNexus.Reply.created("{\"id\":\"" + ROLE + "\",\"name\":\"Dispatcher\"}");

        DelegationService.Result result = delegation.createRole(admin.getId(), json(
                "{\"name\":\"Dispatcher\",\"description\":\"Watches the map\",\"permissions\":[\""
                        + Catalog.LIVE_VIEW + "\",\"" + Catalog.DEVICES_VIEW + "\",\"" + Catalog.LIVE_VIEW + "\"]}"));

        assertEquals(201, result.status());
        JsonNode sent = json(last().body());
        assertEquals(2, sent.path("permissions").size(), "duplicates are dropped");
        assertEquals(SUBJECT_1, sent.path("acting_user_id").asText());
        assertEquals("Dispatcher", sent.path("name").asText());
    }

    @Test
    public void createRoleRefusesMalformedRoles() {
        for (String text : List.of("{}", "{\"name\":\"X\"}", "{\"name\":\"X\",\"permissions\":[]}",
                "{\"name\":\"X\",\"permissions\":[\"NOT A KEY\"]}", "{\"name\":\"X\",\"permissions\":[1]}",
                "{\"name\":\"X\",\"permissions\":\"all\"}", "[]", "\"x\"")) {
            JsonNode body = json(text);

            assertEquals(422, refusedCall(() -> delegation.createRole(admin.getId(), body)).getStatus(), text);
        }
        assertEquals(0, delegationCalls());
    }

    @Test
    public void updateRoleSendsOnlyWhatChanged() {
        reply = FakeNexus.Reply.ok("{\"id\":\"" + ROLE + "\"}");

        delegation.updateRole(admin.getId(), ROLE, json("{\"description\":null}"));

        FakeNexus.Call call = last();
        assertEquals("PUT", call.method());
        assertEquals(BASE + "/roles/" + ROLE, call.path());
        JsonNode sent = json(call.body());
        assertTrue(sent.has("description") && sent.get("description").isNull());
        assertFalse(sent.has("name"));
        assertFalse(sent.has("permissions"));
    }

    @Test
    public void updateRoleWithNothingToChangeIsRefused() {
        assertEquals(422, refusedCall(() -> delegation.updateRole(admin.getId(), ROLE, json("{}"))).getStatus());
    }

    @Test
    public void deleteRoleIsADelete() {
        reply = FakeNexus.Reply.ok("null");

        delegation.deleteRole(admin.getId(), ROLE);

        assertEquals("DELETE", last().method());
        assertEquals(BASE + "/roles/" + ROLE, last().path());
    }

    // ---------------------------------------------------------------------------------------------------------
    // What OptiNexus refuses, and what is wrong with it

    private DelegationException refusedBy(int status, String code, String message, String details) {
        reply = new FakeNexus.Reply(status, "{\"success\":false,\"error\":{\"code\":\"" + code + "\",\"message\":\""
                + message + "\",\"details\":" + details + "}}", Map.of());
        return refusedCall(() -> delegation.deleteRole(admin.getId(), ROLE));
    }

    @Test
    public void refusalsOfTheUserKeepTheirStatusAndAreNamedInOptiRadarsVocabulary() {
        DelegationException notAdmin = refusedBy(403, "ACTOR_NOT_TENANT_ADMIN", "No", "null");
        assertEquals(403, notAdmin.getStatus());
        assertEquals("delegation_actor_not_tenant_admin", notAdmin.getCode());
        assertEquals("ACTOR_NOT_TENANT_ADMIN", notAdmin.getNexusCode());
        assertNull(notAdmin.getDetails());

        DelegationException inUse = refusedBy(409, "ROLE_IN_USE", "Role in use", "null");
        assertEquals(409, inUse.getStatus());
        assertEquals("delegation_role_in_use", inUse.getCode());

        DelegationException notDelegable = refusedBy(422, "PERMISSION_NOT_DELEGABLE", "Not delegable",
                "{\"permissions\":[\"optiradar.commands.send\"]}");
        assertEquals(422, notDelegable.getStatus());
        assertEquals("optiradar.commands.send", notDelegable.getDetails().path("permissions").get(0).asText());

        assertEquals(404, refusedBy(404, "ROLE_NOT_EDITABLE", "x", "null").getStatus());
        assertEquals(403, refusedBy(403, "TENANT_NOT_ACTIVE", "x", "null").getStatus());
        assertEquals(403, refusedBy(403, "APPLICATION_NOT_SUBSCRIBED", "x", "null").getStatus());
    }

    @Test
    public void aValidationFailureAt400BecomesA422() {
        assertEquals(422, refusedBy(400, "VALIDATION_ERROR", "bad", "{\"name\":[\"required\"]}").getStatus());
    }

    @Test
    public void aWronglySetUpServiceAccountIsAnOperatorProblemNotTheUsers() {
        for (String code : List.of("SERVICE_ACCOUNT_NOT_BOUND", "TENANT_MISMATCH", "APPLICATION_NOT_DELEGABLE")) {
            DelegationException e = refusedBy(403, code, "x", "null");
            assertEquals(503, e.getStatus(), code);
            assertEquals(DelegationException.MISCONFIGURED, e.getCode(), code);
            assertEquals(code, e.getNexusCode());
        }
    }

    @Test
    public void anUnknownStatusIsNotPassedOn() {
        DelegationException e = refusedBy(418, "TEAPOT", "x", "null");

        assertEquals(502, e.getStatus());
        assertEquals(DelegationException.UNEXPECTED, e.getCode());
    }

    @Test
    public void longMessagesAreShortened() {
        DelegationException e = refusedBy(409, "ROLE_IN_USE", "x".repeat(2000), "null");

        assertEquals(300, e.getMessage().length());
    }

    @Test
    public void outagesAnswer503WithRetryAfter() {
        reply = FakeNexus.Reply.error(503, "UNAVAILABLE", "down").withHeader("Retry-After", "12");

        DelegationException e = refusedCall(() -> delegation.catalog(admin.getId()));

        assertEquals(503, e.getStatus());
        assertEquals(DelegationException.UNAVAILABLE, e.getCode());
        assertEquals(12, e.getRetryAfterSeconds());
    }

    @Test
    public void aRefusedTokenAndAnUnreachableServerAreOutagesToo() {
        nexus.setTokenStatus(401);
        assertEquals(503, refusedCall(() -> delegation.catalog(admin.getId())).getStatus());

        Config config = config();
        config.setString(Keys.OPTINEXUS_BASE_URL, "http://127.0.0.1:1");
        DelegationService unreachable = new DelegationService(service(config), nexusClient);
        assertEquals(503, refusedCall(() -> unreachable.catalog(admin.getId())).getStatus());
    }

    @Test
    public void exceptionMapperUsesTheSharedJsonShape() {
        DelegationException e = refusedBy(422, "PERMISSION_NOT_DELEGABLE", "Not delegable",
                "{\"permissions\":[\"optiradar.commands.send\"]}");

        Response response = DelegationExceptionMapper.response(e, "ref-12345678");

        assertEquals(422, response.getStatus());
        assertEquals("ref-12345678", response.getHeaderString("X-Correlation-Id"));
        assertEquals("no-store", response.getHeaderString("Cache-Control"));
        JsonNode body = json((String) response.getEntity());
        assertEquals("delegation_permission_not_delegable", body.path("error").asText());
        assertEquals("PERMISSION_NOT_DELEGABLE", body.path("nexusCode").asText());
        assertEquals("ref-12345678", body.path("correlationId").asText());
        assertEquals("optiradar.commands.send", body.path("details").path("permissions").get(0).asText());
    }

}
