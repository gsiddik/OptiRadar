package org.traccar.governance;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A stand-in for the parts of OptiNexus that OptiRadar calls, built from the documented JSON of
 * docs/ecosystem/GOVERNANCE_CONTRACTS.md and the controllers that serve it: the OAuth client-credentials token
 * endpoint (a token is bound to the scope it was asked for, as in OptiNexus), the response envelope
 * {@code {success, data|error}} and the payloads of effective-permissions, commercial-context and product-context.
 */
public class FakeNexus implements AutoCloseable {

    public record Call(String method, String path, String query, String authorization, String scope, String body) {
    }

    public record Reply(int status, String body, Map<String, String> headers) {

        public static Reply ok(String dataJson) {
            return new Reply(200, "{\"success\":true,\"data\":" + dataJson + "}", Map.of());
        }

        public static Reply created(String dataJson) {
            return new Reply(201, "{\"success\":true,\"data\":" + dataJson + "}", Map.of());
        }

        public static Reply error(int status, String code, String message) {
            return new Reply(status, "{\"success\":false,\"error\":{\"code\":\"" + code + "\",\"message\":\""
                    + message + "\"}}", Map.of());
        }

        public static Reply raw(int status, String body) {
            return new Reply(status, body, Map.of());
        }

        public Reply withHeader(String name, String value) {
            Map<String, String> copy = new LinkedHashMap<>(headers);
            copy.put(name, value);
            return new Reply(status, body, copy);
        }
    }

    public interface Handler {
        Reply handle(Call call) throws Exception;
    }

    private record Route(String method, String prefix, String scope, Handler handler) {
    }

    private final List<Call> calls = new CopyOnWriteArrayList<>();
    private final List<Route> routes = new CopyOnWriteArrayList<>();
    private final AtomicInteger tokens = new AtomicInteger();
    private final HttpServer server;

    private volatile int tokenStatus = 200;
    private volatile long delayMillis;

    public FakeNexus() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newFixedThreadPool(16));
        server.createContext("/", this::dispatch);
        server.start();
    }

    /** Status of the token endpoint; anything but 200 refuses the service account. */
    public void setTokenStatus(int status) {
        this.tokenStatus = status;
    }

    /** Milliseconds every non-token answer is delayed (single-flight and timeout tests). */
    public void setDelayMillis(long millis) {
        this.delayMillis = millis;
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    public FakeNexus route(String method, String prefix, String scope, Handler handler) {
        routes.add(0, new Route(method, prefix, scope, handler));
        return this;
    }

    public List<Call> calls() {
        return new ArrayList<>(calls);
    }

    public List<Call> calls(String path) {
        return calls.stream().filter(call -> call.path().startsWith(path)).toList();
    }

    public void reset() {
        calls.clear();
        routes.clear();
        tokenStatus = 200;
        delayMillis = 0;
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void dispatch(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        if (path.equals("/api/v1/oauth/token")) {
            tokenEndpoint(exchange, body);
            return;
        }
        String scope = null;
        if (authorization != null && authorization.startsWith("Bearer token-")) {
            String[] parts = authorization.substring("Bearer token-".length()).split("\\.", 2);
            scope = parts.length == 2 ? parts[1] : null;
        }
        Call call = new Call(method, path, exchange.getRequestURI().getRawQuery(), authorization, scope, body);
        calls.add(call);
        try {
            if (delayMillis > 0) {
                Thread.sleep(delayMillis);
            }
            Reply reply = null;
            for (Route route : routes) {
                if (route.method().equals(method) && path.startsWith(route.prefix())) {
                    if (authorization == null || scope == null) {
                        reply = Reply.error(401, "UNAUTHENTICATED", "Unauthenticated");
                    } else if (route.scope() != null && !route.scope().equals(scope)) {
                        reply = Reply.error(403, "INSUFFICIENT_SCOPE", "Scope " + route.scope() + " is required");
                    } else {
                        reply = route.handler().handle(call);
                    }
                    break;
                }
            }
            if (reply == null) {
                reply = Reply.error(404, "NOT_FOUND", "Not found");
            }
            respond(exchange, reply);
        } catch (Exception e) {
            respond(exchange, Reply.error(500, "SERVER_ERROR", "boom"));
        }
    }

    private void tokenEndpoint(HttpExchange exchange, String body) throws IOException {
        if (tokenStatus != 200) {
            respond(exchange, Reply.raw(tokenStatus, "{\"error\":\"invalid_client\"}"));
            return;
        }
        String scope = "";
        for (String pair : body.split("&")) {
            if (pair.startsWith("scope=")) {
                scope = java.net.URLDecoder.decode(pair.substring(6), StandardCharsets.UTF_8);
            }
        }
        int n = tokens.incrementAndGet();
        calls.add(new Call("POST", "/api/v1/oauth/token", null, null, scope, body.replaceAll("client_secret=[^&]*",
                "client_secret=***")));
        respond(exchange, Reply.raw(200, "{\"access_token\":\"token-" + n + "." + scope
                + "\",\"token_type\":\"Bearer\",\"expires_in\":3600}"));
    }

    private void respond(HttpExchange exchange, Reply reply) throws IOException {
        byte[] bytes = reply.body().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        reply.headers().forEach((name, value) -> exchange.getResponseHeaders().add(name, value));
        exchange.sendResponseHeaders(reply.status(), bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    // ---------------------------------------------------------------------------------------------------------
    // Documented payloads

    public static String json(Object value) {
        try {
            return new ObjectMapper().writeValueAsString(value);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** POST /authorization/effective-permissions (schema 1.0). */
    public static String effectivePermissions(
            String userId, String tenantId, String application, boolean allowed, String denyReason, int ttl,
            String... permissionKeys) {
        List<Map<String, String>> permissions = new ArrayList<>();
        for (String key : permissionKeys) {
            permissions.add(Map.of("permission", key, "scope", "TENANT"));
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("schema_version", "1.0");
        data.put("user_id", userId);
        data.put("tenant_id", tenantId);
        data.put("application_code", application);
        data.put("allowed", allowed);
        data.put("deny_reason", denyReason);
        data.put("permissions", permissions);
        data.put("evaluated_at", "2026-10-17T10:00:00+00:00");
        data.put("ttl_seconds", ttl);
        return json(data);
    }

    /** GET /tenants/{tenant}/commercial-context. */
    public static String commercialContext(
            String tenantId, String status, List<String> applications, List<String> capabilitiesOn,
            List<String> capabilitiesOff) {
        List<Map<String, Object>> effective = new ArrayList<>();
        for (String code : applications) {
            effective.add(Map.of("entitlement_type", "APPLICATION", "entitlement_key", code, "value", true));
        }
        for (String code : capabilitiesOn) {
            effective.add(Map.of("entitlement_type", "CAPABILITY", "entitlement_key", code, "value", true));
        }
        for (String code : capabilitiesOff) {
            effective.add(Map.of("entitlement_type", "CAPABILITY", "entitlement_key", code, "value", false));
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("tenant_id", tenantId);
        data.put("tenant_status", status);
        data.put("subscriptions", List.of());
        data.put("applications_enabled", applications);
        data.put("effective_entitlements", effective);
        return json(data);
    }

    /** POST /authorization/product-context (schema 1.0). */
    public static String productContext(
            String userId, String tenantId, String tenantCode, String application, boolean allowed, String denyReason,
            int ttl, List<Map<String, Object>> products) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("schema_version", "1.0");
        data.put("user_id", userId);
        data.put("tenant", allowed ? Map.of("id", tenantId, "code", tenantCode, "name", "Tenant " + tenantCode) : null);
        data.put("application_code", application);
        data.put("allowed", allowed);
        data.put("deny_reason", denyReason);
        data.put("products", allowed ? products : List.of());
        data.put("evaluated_at", "2026-10-17T10:00:00+00:00");
        data.put("ttl_seconds", ttl);
        return json(data);
    }

}
