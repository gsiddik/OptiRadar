package org.traccar.governance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.api.security.UserPrincipal;

import jakarta.annotation.Priority;
import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Enforces the access OptiNexus granted on every REST route (and, because the MCP tools call the same routes, on the
 * MCP server). It runs after authentication, reads {@link Governed} from the route, asks {@link GovernanceService}
 * and either lets the request through or answers with a JSON body {@code {error, message, permission,
 * correlationId}} and a stable error code. Nothing here decides anything by itself.
 */
@Priority(Priorities.USER + 100)
public class GovernanceRequestFilter implements ContainerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(GovernanceRequestFilter.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final int MAX_BODY = 256 * 1024;
    private static final long OPERATOR_LOG_INTERVAL = 10 * 60 * 1000L;
    private static final Pattern CORRELATION = Pattern.compile("^[A-Za-z0-9._-]{8,64}$");

    private static final Map<Long, Long> OPERATOR_LOGGED = new ConcurrentHashMap<>();

    @Context
    private HttpServletRequest request;

    @Context
    private ResourceInfo resourceInfo;

    @Inject
    private GovernanceService governance;

    /**
     * What a route needs.
     */
    record Requirement(Governed.Access access, List<String> permissions, String rule, boolean selfOnly,
                       boolean integration) {
    }

    @Override
    public void filter(ContainerRequestContext context) throws IOException {
        if (!governance.enabled() || context.getMethod().equals("OPTIONS")) {
            return;
        }
        Method method = resourceInfo.getResourceMethod();
        if (method == null || method.isAnnotationPresent(PermitAll.class)) {
            return;
        }
        if (!(context.getSecurityContext().getUserPrincipal() instanceof UserPrincipal principal)) {
            return;
        }
        long userId = principal.getUserId();
        String verb = context.getMethod();
        String path = context.getUriInfo().getPath();
        Requirement requirement = requirement(method, resourceInfo.getResourceClass(), verb);

        try {
            GovernedPrincipal who = governance.principal(userId);
            switch (who.kind()) {
                case OPERATOR -> noteOperator(userId, verb, path);
                case INTEGRATION -> {
                    if (requirement == null || !requirement.integration() || !isRead(verb)) {
                        throw new GovernanceException(403, GovernanceException.IDENTITY_REQUIRED,
                                "An integration account may only read what its integration needs", null);
                    }
                }
                case DENIED -> throw new GovernanceException(403, who.code(),
                        "This account is not tied to an OptiNexus identity and tenant", null);
                default -> decide(context, who, requirement, verb);
            }
        } catch (GovernanceException e) {
            deny(context, e, userId, verb, path);
        }
    }

    private void decide(ContainerRequestContext context, GovernedPrincipal who, Requirement requirement, String verb)
            throws IOException {
        if (requirement == null) {
            LOGGER.error("Route {} {} has no @Governed answer; refused", verb, context.getUriInfo().getPath());
            throw new GovernanceException(403, GovernanceException.ROUTE_UNMAPPED,
                    "This route is not covered by the access catalog", null);
        }
        switch (requirement.access()) {
            case OPERATOR -> throw new GovernanceException(403, GovernanceException.OPERATOR_ONLY,
                    "Only an OptiRadar administrator may do this", null);
            case SELF -> {
                governance.requireSignedIn(who);
                if (requirement.selfOnly()) {
                    String id = context.getUriInfo().getPathParameters().getFirst("id");
                    if (id != null && !id.equals(String.valueOf(who.userId()))) {
                        throw new GovernanceException(403, GovernanceException.OPERATOR_ONLY,
                                "Tenant users may only use their own account here", null);
                    }
                }
            }
            case DYNAMIC -> governance.require(who, dynamic(context, who, requirement.rule()));
            default -> governance.require(who, requirement.permissions());
        }
    }

    // ---------------------------------------------------------------------------------------------------------
    // Route requirements

    static Requirement requirement(Method method, Class<?> resourceClass, String verb) {
        Governed onMethod = method.getAnnotation(Governed.class);
        Governed onClass = resourceClass.getAnnotation(Governed.class);
        if (onMethod != null) {
            Requirement requirement = fromMethod(onMethod, verb);
            if (requirement != null) {
                return requirement;
            }
        }
        if (onClass == null) {
            return null;
        }
        boolean integration = isRead(verb) && (onMethod != null && onMethod.integration() || onClass.integration());
        if (onClass.access() != Governed.Access.GRANT) {
            return new Requirement(onClass.access(), List.of(), onClass.rule(), onClass.selfOnly(), integration);
        }
        String permission = isRead(verb) ? onClass.read() : onClass.write();
        if (permission.isEmpty()) {
            permission = onClass.value();
        }
        if (permission.isEmpty()) {
            return null;
        }
        return new Requirement(Governed.Access.GRANT, List.of(permission), "", false, integration);
    }

    private static Requirement fromMethod(Governed governed, String verb) {
        boolean integration = isRead(verb) && governed.integration();
        if (governed.access() != Governed.Access.GRANT) {
            return new Requirement(governed.access(), List.of(), governed.rule(), governed.selfOnly(), integration);
        }
        if (!governed.value().isEmpty()) {
            return new Requirement(Governed.Access.GRANT, List.of(governed.value()), "", false, integration);
        }
        return null;
    }

    private static boolean isRead(String verb) {
        return verb.equals("GET") || verb.equals("HEAD");
    }

    // ---------------------------------------------------------------------------------------------------------
    // Rules that depend on the request

    private List<String> dynamic(ContainerRequestContext context, GovernedPrincipal who, String rule)
            throws IOException {
        switch (rule) {
            case "positions.get":
                var query = context.getUriInfo().getQueryParameters();
                return query.containsKey("from") || query.containsKey("id")
                        ? List.of(Catalog.POSITIONS_VIEW) : List.of(Catalog.LIVE_VIEW);
            case "permissions.link":
                return linkPermissions(context, who);
            default:
                throw new GovernanceException(403, GovernanceException.ROUTE_UNMAPPED,
                        "Unknown access rule " + rule, null);
        }
    }

    private static final Map<String, String> LINK_MANAGE = Map.ofEntries(
            Map.entry("geofenceid", Catalog.GEOFENCES_MANAGE),
            Map.entry("notificationid", Catalog.NOTIFICATIONS_MANAGE),
            Map.entry("driverid", Catalog.DRIVERS_MANAGE),
            Map.entry("maintenanceid", Catalog.MAINTENANCE_MANAGE),
            Map.entry("commandid", Catalog.COMMANDS_MANAGE),
            Map.entry("attributeid", Catalog.ATTRIBUTES_MANAGE),
            Map.entry("calendarid", Catalog.CALENDARS_MANAGE),
            Map.entry("orderid", Catalog.ORDERS_MANAGE),
            Map.entry("reportid", Catalog.REPORTS_SCHEDULE));

    /**
     * Links between objects: the caller needs to manage the feature that is attached. Devices and groups are the
     * things things are attached to; linking users to anything is for administrators, except that a user may
     * subscribe themselves to a notification or a scheduled report they manage.
     */
    private List<String> linkPermissions(ContainerRequestContext context, GovernedPrincipal who) throws IOException {
        byte[] body = context.getEntityStream().readNBytes(MAX_BODY + 1);
        if (body.length > MAX_BODY) {
            throw new GovernanceException(403, GovernanceException.PERMISSION_DENIED, "Request too large", null);
        }
        context.setEntityStream(new ByteArrayInputStream(body));
        JsonNode root;
        try {
            root = MAPPER.readTree(body);
        } catch (IOException e) {
            throw new GovernanceException(403, GovernanceException.PERMISSION_DENIED, "Unreadable request", null);
        }
        List<JsonNode> entries = new ArrayList<>();
        if (root != null && root.isArray()) {
            root.forEach(entries::add);
        } else if (root != null && root.isObject()) {
            entries.add(root);
        }
        if (entries.isEmpty()) {
            throw new GovernanceException(403, GovernanceException.PERMISSION_DENIED, "Nothing to link", null);
        }
        Set<String> required = new LinkedHashSet<>();
        for (JsonNode entry : entries) {
            Set<String> keys = new LinkedHashSet<>();
            entry.fieldNames().forEachRemaining(name -> keys.add(name.toLowerCase(Locale.ROOT)));
            if (keys.size() != 2) {
                throw new GovernanceException(403, GovernanceException.PERMISSION_DENIED, "Invalid link", null);
            }
            required.addAll(linkRequirement(keys, entry, who));
        }
        return List.copyOf(required);
    }

    private List<String> linkRequirement(Set<String> keys, JsonNode entry, GovernedPrincipal who) {
        List<String> permissions = new ArrayList<>();
        boolean user = keys.contains("userid");
        if (keys.contains("manageduserid") || user && !selfLink(keys, entry, who)) {
            throw new GovernanceException(403, GovernanceException.OPERATOR_ONLY,
                    "Only an OptiRadar administrator may link users", null);
        }
        boolean attached = false;
        for (String key : keys) {
            String manage = LINK_MANAGE.get(key);
            if (manage != null) {
                permissions.add(manage);
                attached = true;
            } else if (!key.equals("userid") && !key.equals("deviceid") && !key.equals("groupid")
                    && !key.equals("linkeddeviceid")) {
                throw new GovernanceException(403, GovernanceException.PERMISSION_DENIED, "Unknown link " + key, null);
            }
        }
        if (!attached) {
            permissions.add(keys.contains("groupid") ? Catalog.GROUPS_MANAGE : Catalog.DEVICES_MANAGE);
        }
        if (keys.contains("notificationid") && keys.contains("commandid")) {
            permissions.add(Catalog.COMMANDS_SEND);
        }
        return permissions;
    }

    private boolean selfLink(Set<String> keys, JsonNode entry, GovernedPrincipal who) {
        if (!keys.contains("notificationid") && !keys.contains("reportid")) {
            return false;
        }
        for (var fields = entry.fields(); fields.hasNext();) {
            var field = fields.next();
            if (field.getKey().equalsIgnoreCase("userId")) {
                return field.getValue().asLong(-1) == who.userId();
            }
        }
        return false;
    }

    // ---------------------------------------------------------------------------------------------------------
    // Answers

    private void noteOperator(long userId, String verb, String path) {
        long now = System.currentTimeMillis();
        Long last = OPERATOR_LOGGED.get(userId);
        if (last == null || now - last > OPERATOR_LOG_INTERVAL) {
            OPERATOR_LOGGED.put(userId, now);
            LOGGER.info("Local administrator account {} acts outside tenant grants ({} {})", userId, verb, path);
        }
    }

    private void deny(ContainerRequestContext context, GovernanceException e, long userId, String verb, String path) {
        String correlation = correlationId(context);
        if (e.getStatus() == 503) {
            LOGGER.warn("Access not decidable user={} {} {} code={} ref={}", userId, verb, path, e.getCode(),
                    correlation);
        } else {
            LOGGER.info("Access denied user={} {} {} code={} permission={} ref={}", userId, verb, path, e.getCode(),
                    e.getPermission(), correlation);
        }
        if (e.endsSessions()) {
            governance.endSessions(userId);
            try {
                HttpSession session = request.getSession(false);
                if (session != null) {
                    session.invalidate();
                }
            } catch (RuntimeException ignored) {
                // an in-process call (MCP) has no browser session
            }
        }
        context.abortWith(response(e, correlation));
    }

    static Response response(GovernanceException e, String correlation) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", e.getCode());
        body.put("message", e.getStatus() == 503
                ? "Access cannot be checked right now. Try again shortly." : "Access is not granted.");
        if (e.getPermission() != null) {
            body.put("permission", e.getPermission());
        }
        body.put("correlationId", correlation);
        String json;
        try {
            json = MAPPER.writeValueAsString(body);
        } catch (IOException ex) {
            json = "{\"error\":\"" + e.getCode() + "\"}";
        }
        Response.ResponseBuilder builder = Response.status(e.getStatus())
                .type(MediaType.APPLICATION_JSON)
                .header("Cache-Control", "no-store")
                .header("X-Correlation-Id", correlation)
                .entity(json);
        if (e.getRetryAfterSeconds() > 0) {
            builder.header("Retry-After", e.getRetryAfterSeconds());
        }
        return builder.build();
    }

    static String correlationId(ContainerRequestContext context) {
        String given = context.getHeaderString("X-Correlation-Id");
        if (given != null && CORRELATION.matcher(given).matches()) {
            return given;
        }
        return UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }

}
