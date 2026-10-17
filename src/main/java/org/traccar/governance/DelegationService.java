package org.traccar.governance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Lets an Admin Tenant manage the users and custom roles of their own tenant for OptiRadar from OptiRadar's screens.
 * Nothing is stored here: every call is forwarded to the OptiNexus delegation API
 * ({@code /api/v1/delegation/tenants/{tenant}/...}, scope {@code tenant.delegate}) with OptiRadar's own service
 * account.
 *
 * <p>The tenant and the acting user always come from the signed-in account's identity link, never from the request.
 * OptiNexus verifies on every call that the actor is an active Admin Tenant of that tenant with access to OptiRadar and
 * decides which permissions are delegable; this class only checks the shape of what it forwards.</p>
 */
@Singleton
public class DelegationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(DelegationService.class);

    public static final String SCOPE = "tenant.delegate";

    private static final Pattern UUID = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
    private static final Pattern PERMISSION = Pattern.compile("^[a-z][a-z0-9_]*(\\.[a-z0-9_]+)+$");
    private static final Set<Integer> PASSED_STATUSES = Set.of(403, 404, 409, 422);
    /** Answers that mean OptiRadar's service account is set up wrongly: a problem for the operator, not the user. */
    private static final Set<String> SETUP_CODES = Set.of(
            "SERVICE_ACCOUNT_NOT_BOUND", "TENANT_MISMATCH", "APPLICATION_NOT_DELEGABLE", "INSUFFICIENT_SCOPE",
            "UNAUTHENTICATED", "HTTP_403", "HTTP_401");
    private static final int MAX_MESSAGE = 300;

    /**
     * What OptiNexus answered, for the web app.
     */
    public record Result(int status, JsonNode data, JsonNode meta) {
    }

    private final GovernanceService governance;
    private final NexusClient nexus;

    @Inject
    public DelegationService(GovernanceService governance, NexusClient nexus) {
        this.governance = governance;
        this.nexus = nexus;
    }

    // ---------------------------------------------------------------------------------------------------------
    // Operations

    public Result catalog(long userId) {
        Actor actor = actor(userId);
        return get(actor, "/catalog", Map.of());
    }

    public Result listUsers(long userId, String search, Integer perPage) {
        Actor actor = actor(userId);
        Map<String, String> query = new LinkedHashMap<>();
        if (search != null && !search.isBlank()) {
            if (search.length() > 100) {
                throw invalid("search", "too long");
            }
            query.put("search", search.trim());
        }
        query.put("per_page", String.valueOf(Math.max(1, Math.min(100, perPage != null ? perPage : 25))));
        return get(actor, "/users", query);
    }

    public Result addUser(long userId, JsonNode body) {
        Actor actor = actor(userId);
        Map<String, Object> payload = new LinkedHashMap<>();
        Map<String, String> problems = new LinkedHashMap<>();
        only(body, Set.of("email", "name", "initial_password", "role_ids"), problems);
        String email = text(body, "email", problems, true, 255);
        if (email != null && !EMAIL.matcher(email).matches()) {
            problems.put("email", "invalid");
        }
        payload.put("email", email);
        payload.put("name", text(body, "name", problems, true, 255));
        String password = text(body, "initial_password", problems, false, 128);
        if (password != null) {
            if (password.length() < 12) {
                problems.put("initial_password", "too short");
            }
            payload.put("initial_password", password);
        }
        if (body.has("role_ids")) {
            payload.put("role_ids", uuids(body, "role_ids", problems, 20));
        }
        fail(problems);
        Result result = send(actor, "POST", "/users", payload);
        String created = result.data().path("id").asText(null);
        if (created != null && UUID.matcher(created).matches()) {
            governance.invalidateSubject(actor.tenantId(), created);
        }
        return result;
    }

    public Result setUserRoles(long userId, String user, JsonNode body) {
        Actor actor = actor(userId);
        String target = id(user, "user");
        Map<String, String> problems = new LinkedHashMap<>();
        only(body, Set.of("role_ids"), problems);
        if (!body.has("role_ids")) {
            problems.put("role_ids", "required");
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("role_ids", uuids(body, "role_ids", problems, 20));
        fail(problems);
        Result result = send(actor, "PUT", "/users/" + target + "/roles", payload);
        governance.invalidateSubject(actor.tenantId(), target);
        return result;
    }

    public Result removeUser(long userId, String user) {
        Actor actor = actor(userId);
        String target = id(user, "user");
        Result result = send(actor, "DELETE", "/users/" + target, null);
        governance.invalidateSubject(actor.tenantId(), target);
        return result;
    }

    public Result createRole(long userId, JsonNode body) {
        Actor actor = actor(userId);
        Map<String, Object> payload = rolePayload(body, true);
        return send(actor, "POST", "/roles", payload);
    }

    public Result updateRole(long userId, String roleId, JsonNode body) {
        Actor actor = actor(userId);
        String role = id(roleId, "role");
        Map<String, Object> payload = rolePayload(body, false);
        Result result = send(actor, "PUT", "/roles/" + role, payload);
        governance.invalidateTenant(actor.tenantId());
        return result;
    }

    public Result deleteRole(long userId, String roleId) {
        Actor actor = actor(userId);
        String role = id(roleId, "role");
        Result result = send(actor, "DELETE", "/roles/" + role, null);
        governance.invalidateTenant(actor.tenantId());
        return result;
    }

    // ---------------------------------------------------------------------------------------------------------
    // Who and where

    private record Actor(String subject, String tenantId) {
    }

    private Actor actor(long userId) {
        if (!governance.enabled()) {
            throw new DelegationException(404, DelegationException.DISABLED,
                    "Access management through OptiNexus is off on this server");
        }
        GovernedPrincipal principal = governance.principal(userId);
        if (principal.kind() != GovernedPrincipal.Kind.CENTRAL) {
            throw new DelegationException(403, DelegationException.ACTOR_REQUIRED,
                    "Only a user signed in through OptiNexus can manage access");
        }
        return new Actor(principal.subject(), principal.tenantId());
    }

    private String base(Actor actor) {
        return "/api/v1/delegation/tenants/" + actor.tenantId();
    }

    // ---------------------------------------------------------------------------------------------------------
    // Calls

    private Result get(Actor actor, String path, Map<String, String> query) {
        StringBuilder url = new StringBuilder(base(actor)).append(path).append('?');
        for (Map.Entry<String, String> entry : query.entrySet()) {
            url.append(entry.getKey()).append('=').append(encode(entry.getValue())).append('&');
        }
        url.append("acting_user_id=").append(actor.subject());
        return call("GET", url.toString(), null);
    }

    private Result send(Actor actor, String method, String path, Map<String, Object> payload) {
        if (method.equals("DELETE")) {
            return call(method, base(actor) + path + "?acting_user_id=" + actor.subject(), null);
        }
        Map<String, Object> body = new LinkedHashMap<>(payload);
        body.put("acting_user_id", actor.subject());
        return call(method, base(actor) + path, body);
    }

    private Result call(String method, String url, Object body) {
        try {
            NexusClient.Envelope envelope = nexus.request(method, SCOPE, url, body);
            return new Result(envelope.status(), envelope.data(), envelope.meta());
        } catch (NexusClient.UnavailableException e) {
            LOGGER.warn("OptiNexus delegation call did not complete: {}", e.getMessage());
            throw new DelegationException(503, DelegationException.UNAVAILABLE, null,
                    "OptiNexus cannot be reached right now", null, Math.max(1, e.getRetryAfterSeconds()));
        } catch (NexusClient.RejectedException e) {
            throw translate(e);
        }
    }

    static DelegationException translate(NexusClient.RejectedException e) {
        String nexusCode = e.getCode() != null ? e.getCode() : "UNKNOWN";
        if (SETUP_CODES.contains(nexusCode)) {
            LOGGER.error("OptiNexus refused the OptiRadar service account for delegation ({}): bind it to the "
                    + "optiradar application with the tenant.delegate scope", nexusCode);
            return new DelegationException(503, DelegationException.MISCONFIGURED, nexusCode,
                    "Access management is not set up correctly between OptiRadar and OptiNexus", null, 0);
        }
        int status = e.getStatus() == 400 ? 422 : e.getStatus();
        String message = e.getMessage() != null && e.getMessage().length() > MAX_MESSAGE
                ? e.getMessage().substring(0, MAX_MESSAGE) : e.getMessage();
        if (!PASSED_STATUSES.contains(status)) {
            LOGGER.warn("OptiNexus delegation answered HTTP {} ({})", e.getStatus(), nexusCode);
            return new DelegationException(502, DelegationException.UNEXPECTED, nexusCode,
                    "OptiNexus gave an answer that OptiRadar does not know", null, 0);
        }
        return new DelegationException(status, "delegation_" + nexusCode.toLowerCase(Locale.ROOT), nexusCode,
                message, e.getDetails() != null && !e.getDetails().isNull() ? e.getDetails() : null, 0);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    // ---------------------------------------------------------------------------------------------------------
    // Shape of what is forwarded

    private Map<String, Object> rolePayload(JsonNode body, boolean creating) {
        Map<String, String> problems = new LinkedHashMap<>();
        only(body, Set.of("name", "description", "permissions"), problems);
        Map<String, Object> payload = new LinkedHashMap<>();
        if (creating || body.has("name")) {
            String name = text(body, "name", problems, true, 120);
            payload.put("name", name);
        }
        if (body.has("description")) {
            payload.put("description", body.get("description").isNull() ? null
                    : text(body, "description", problems, false, 500));
        }
        if (creating || body.has("permissions")) {
            List<String> permissions = new ArrayList<>();
            JsonNode node = body.get("permissions");
            if (node == null || !node.isArray() || node.isEmpty() || node.size() > 200) {
                problems.put("permissions", "1 to 200 permission keys are required");
            } else {
                Set<String> seen = new HashSet<>();
                for (JsonNode entry : node) {
                    String key = entry.isTextual() ? entry.asText() : null;
                    if (key == null || key.length() > 150 || !PERMISSION.matcher(key).matches()) {
                        problems.put("permissions", "contains an invalid permission key");
                        break;
                    }
                    if (seen.add(key)) {
                        permissions.add(key);
                    }
                }
            }
            payload.put("permissions", permissions);
        }
        if (!creating && payload.isEmpty() && problems.isEmpty()) {
            problems.put("body", "nothing to change");
        }
        fail(problems);
        return payload;
    }

    private static void only(JsonNode body, Set<String> allowed, Map<String, String> problems) {
        if (body == null || !body.isObject()) {
            throw invalid("body", "a JSON object is required");
        }
        body.fieldNames().forEachRemaining(name -> {
            if (!allowed.contains(name)) {
                problems.put(name, "unknown field");
            }
        });
    }

    private static String text(JsonNode body, String field, Map<String, String> problems, boolean required, int max) {
        JsonNode node = body.get(field);
        if (node == null || node.isNull()) {
            if (required) {
                problems.put(field, "required");
            }
            return null;
        }
        if (!node.isTextual()) {
            problems.put(field, "must be text");
            return null;
        }
        String value = node.asText().trim();
        if (value.isEmpty()) {
            if (required) {
                problems.put(field, "required");
            }
            return null;
        }
        if (value.length() > max) {
            problems.put(field, "too long");
            return null;
        }
        return value;
    }

    private static ArrayNode uuids(JsonNode body, String field, Map<String, String> problems, int max) {
        ArrayNode result = JsonNodeFactory.instance.arrayNode();
        JsonNode node = body.get(field);
        if (node == null) {
            return result;
        }
        if (!node.isArray() || node.size() > max) {
            problems.put(field, "must be a list of at most " + max + " ids");
            return result;
        }
        for (JsonNode entry : node) {
            if (!entry.isTextual() || !UUID.matcher(entry.asText()).matches()) {
                problems.put(field, "contains an id that is not valid");
                return result;
            }
            result.add(entry.asText().toLowerCase(Locale.ROOT));
        }
        return result;
    }

    private static String id(String value, String what) {
        if (value == null || !UUID.matcher(value).matches()) {
            throw invalid(what, "not a valid id");
        }
        return value.toLowerCase(Locale.ROOT);
    }

    private static DelegationException invalid(String field, String reason) {
        return new DelegationException(422, DelegationException.INVALID_REQUEST, null,
                "The request is not valid", detail(Map.of(field, reason)), 0);
    }

    private static void fail(Map<String, String> problems) {
        if (!problems.isEmpty()) {
            throw new DelegationException(422, DelegationException.INVALID_REQUEST, null,
                    "The request is not valid", detail(problems), 0);
        }
    }

    private static JsonNode detail(Map<String, String> problems) {
        var node = JsonNodeFactory.instance.objectNode();
        problems.forEach(node::put);
        return node;
    }

}
