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
package org.traccar.database;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.traccar.config.Config;
import org.traccar.config.Keys;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OptinexusEntitlementsTest {

    private static final String TENANT = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";
    private static final long START = 1_800_000_000_000L;

    private record Call(String path, String authorization, String body) { }

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final List<Call> calls = new CopyOnWriteArrayList<>();
    private final AtomicInteger tokenCounter = new AtomicInteger();
    private final AtomicLong clock = new AtomicLong(START);

    private HttpServer server;
    private Client client;
    private int checkStatus = 200;
    private String checkBody = "{\"success\":true,\"data\":{\"allowed\":true}}";

    @BeforeEach
    public void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/oauth/token", exchange -> {
            record(exchange);
            respond(exchange, 200, "{\"access_token\":\"token-" + tokenCounter.incrementAndGet()
                    + "\",\"expires_in\":3600}");
        });
        server.createContext("/api/v1/entitlements/check", exchange -> {
            record(exchange);
            respond(exchange, checkStatus, checkBody);
        });
        server.start();
        client = ClientBuilder.newClient();
    }

    @AfterEach
    public void tearDown() {
        client.close();
        server.stop(0);
    }

    private void record(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        calls.add(new Call(exchange.getRequestURI().getPath(),
                exchange.getRequestHeaders().getFirst("Authorization"), body));
    }

    private void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private OptinexusEntitlements entitlements() {
        Config config = new Config();
        config.setString(Keys.OPTINEXUS_BASE_URL, "http://127.0.0.1:" + server.getAddress().getPort() + "/");
        config.setString(Keys.OPTINEXUS_CLIENT_ID, "radar-client");
        config.setString(Keys.OPTINEXUS_CLIENT_SECRET, "radar-secret");
        config.setString(Keys.OPTINEXUS_ENTITLEMENTS_ENFORCE, "true");
        config.setString(Keys.OPTINEXUS_ENTITLEMENTS_TTL, "300");
        return new OptinexusEntitlements(config, client, objectMapper) {
            @Override
            protected long now() {
                return clock.get();
            }
        };
    }

    private long checks() {
        return calls.stream().filter(call -> call.path().equals("/api/v1/entitlements/check")).count();
    }

    @Test
    public void asksOptiNexusForTheFeatureOfTheTenantWithTheCheckScope() throws Exception {
        assertTrue(entitlements().allows(TENANT, "trip_reports"));

        Call token = calls.get(0);
        assertTrue(token.body().contains("scope=entitlement.check"));
        Call check = calls.get(1);
        assertEquals("Bearer token-1", check.authorization());
        JsonNode body = objectMapper.readTree(check.body());
        assertEquals(TENANT, body.get("tenant_id").asText());
        assertEquals("optiradar", body.get("application_code").asText());
        assertEquals("trip_reports", body.get("entitlement_key").asText());
    }

    @Test
    public void reportsAFeatureThePlanDoesNotInclude() {
        checkBody = "{\"success\":true,\"data\":{\"allowed\":false}}";

        assertFalse(entitlements().allows(TENANT, "geofences"));
    }

    @Test
    public void reusesAnAnswerUntilItExpires() {
        OptinexusEntitlements entitlements = entitlements();

        entitlements.allows(TENANT, "trip_reports");
        entitlements.allows(TENANT, "trip_reports");
        assertEquals(1, checks());

        clock.addAndGet(TimeUnit.SECONDS.toMillis(301));
        entitlements.allows(TENANT, "trip_reports");
        assertEquals(2, checks());
        assertEquals(1, tokenCounter.get());
    }

    @Test
    public void keepsTheLastAnswerWhenOptiNexusFails() {
        OptinexusEntitlements entitlements = entitlements();
        assertTrue(entitlements.allows(TENANT, "trip_reports"));

        checkStatus = 503;
        clock.addAndGet(TimeUnit.SECONDS.toMillis(301));

        assertTrue(entitlements.allows(TENANT, "trip_reports"));
    }

    @Test
    public void refusesAFeatureWhenThereIsNoAnswerAtAll() {
        checkStatus = 503;

        assertFalse(entitlements().allows(TENANT, "trip_reports"));
    }

    @Test
    public void renewsTheTokenOnceAfterAnUnauthorizedAnswer() {
        checkStatus = 401;

        assertFalse(entitlements().allows(TENANT, "trip_reports"));

        assertEquals(2, checks());
        assertEquals(2, tokenCounter.get());
    }

}
