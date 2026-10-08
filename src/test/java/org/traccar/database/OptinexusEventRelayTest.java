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
import org.traccar.model.OptinexusOutboxEvent;
import org.traccar.storage.MemoryStorage;
import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Request;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OptinexusEventRelayTest {

    private static final String TENANT = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";
    private static final long START = 1_800_000_000_000L;

    private record Call(String path, String authorization, String body) { }

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final List<Call> calls = new CopyOnWriteArrayList<>();
    private final AtomicInteger tokenCounter = new AtomicInteger();
    private final AtomicLong clock = new AtomicLong(START);

    private HttpServer server;
    private Client client;
    private Storage storage;
    private Function<Call, int[]> eventStatus = call -> new int[] {201};
    private String eventBody = "{\"data\":{}}";
    private int tokenStatus = 200;

    @BeforeEach
    public void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/oauth/token", exchange -> {
            record(exchange);
            if (tokenStatus == 200) {
                respond(exchange, 200, "{\"access_token\":\"token-" + tokenCounter.incrementAndGet()
                        + "\",\"expires_in\":3600}");
            } else {
                respond(exchange, tokenStatus, "{\"error\":\"invalid_client\"}");
            }
        });
        server.createContext("/api/v1/events", exchange -> {
            Call call = record(exchange);
            respond(exchange, eventStatus.apply(call)[0], eventBody);
        });
        server.start();
        client = ClientBuilder.newClient();
        storage = new MemoryStorage();
    }

    @AfterEach
    public void tearDown() {
        client.close();
        server.stop(0);
    }

    private Call record(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Call call = new Call(exchange.getRequestURI().getPath(),
                exchange.getRequestHeaders().getFirst("Authorization"), body);
        calls.add(call);
        return call;
    }

    private void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private OptinexusEventRelay relay() {
        return relay("http://127.0.0.1:" + server.getAddress().getPort(), 20);
    }

    private OptinexusEventRelay relay(String baseUrl, int maxAttempts) {
        Config config = new Config();
        config.setString(Keys.OPTINEXUS_BASE_URL, baseUrl + "/");
        config.setString(Keys.OPTINEXUS_CLIENT_ID, "radar-client");
        config.setString(Keys.OPTINEXUS_CLIENT_SECRET, "radar-secret");
        config.setString(Keys.OPTINEXUS_EVENTS_MAX_ATTEMPTS, String.valueOf(maxAttempts));
        return new OptinexusEventRelay(config, storage, client, objectMapper) {
            @Override
            protected long now() {
                return clock.get();
            }
        };
    }

    private OptinexusOutboxEvent addRow(String eventKey) throws StorageException {
        OptinexusOutboxEvent row = new OptinexusOutboxEvent();
        row.setEventUuid(UUID.randomUUID().toString());
        row.setEventKey(eventKey);
        row.setTenantId(TENANT);
        row.setDeviceId(10);
        row.setOccurredAt(new Date(START - 5_000));
        row.setPayload("{\"aggregate_type\":\"device\",\"aggregate_id\":\"10\",\"payload\":{\"device_name\":\"Truck\"}}");
        row.setId(storage.addObject(row, new Request(new Columns.Exclude("id"))));
        return row;
    }

    private long eventCalls() {
        return calls.stream().filter(call -> call.path().equals("/api/v1/events")).count();
    }

    private long tokenCalls() {
        return calls.stream().filter(call -> call.path().equals("/api/v1/oauth/token")).count();
    }

    private void advance(long amount, TimeUnit unit) {
        clock.addAndGet(unit.toMillis(amount));
    }

    @Test
    public void deliversAPendingEventUnderItsOwnIdAndAsksForOneTokenForTheBatch() throws Exception {
        OptinexusOutboxEvent first = addRow("optiradar.device.online");
        OptinexusOutboxEvent second = addRow("optiradar.geofence.entered");

        var result = relay().relay();

        assertEquals(2, result.delivered());
        assertEquals(1, tokenCalls());
        List<Call> events = calls.stream().filter(call -> call.path().equals("/api/v1/events")).toList();
        assertEquals("Bearer token-1", events.get(0).authorization());
        JsonNode body = objectMapper.readTree(events.get(0).body());
        assertEquals(first.getEventUuid(), body.get("event_id").asText());
        assertEquals("optiradar.device.online", body.get("event_key").asText());
        assertEquals(TENANT, body.get("tenant_id").asText());
        assertEquals("1", body.get("event_version").asText());
        assertEquals("device:10", body.get("correlation_id").asText());
        assertEquals("Truck", body.get("data").get("payload").get("device_name").asText());
        assertEquals(second.getEventUuid(), objectMapper.readTree(events.get(1).body()).get("event_id").asText());
        assertEquals(OptinexusOutboxEvent.STATUS_DELIVERED, first.getStatus());
        assertNotNull(first.getDeliveredAt());
        assertEquals(1, first.getAttempts());
    }

    @Test
    public void asksForTheEventWriteScopeWithTheClientCredentials() throws Exception {
        addRow("optiradar.device.online");

        relay().relay();

        String form = calls.stream().filter(call -> call.path().equals("/api/v1/oauth/token")).findFirst()
                .orElseThrow().body();
        assertTrue(form.contains("grant_type=client_credentials"), form);
        assertTrue(form.contains("client_id=radar-client"), form);
        assertTrue(form.contains("client_secret=radar-secret"), form);
        assertTrue(form.contains("scope=event.write"), form);
    }

    @Test
    public void aServerErrorKeepsTheEventPendingAndRetriesItLaterUnderTheSameId() throws Exception {
        OptinexusOutboxEvent row = addRow("optiradar.device.offline");
        eventStatus = call -> new int[] {503};
        var relay = relay();

        var first = relay.relay();
        assertEquals(1, first.retrying());
        assertEquals(OptinexusOutboxEvent.STATUS_PENDING, row.getStatus());
        assertEquals(1, row.getAttempts());
        assertEquals("HTTP 503", row.getLastError());

        // Still inside the two minute backoff: nothing is sent.
        advance(90, TimeUnit.SECONDS);
        assertEquals(0, relay.relay().delivered() + relay.relay().retrying());
        assertEquals(1, eventCalls());

        eventStatus = call -> new int[] {201};
        advance(40, TimeUnit.SECONDS);
        assertEquals(1, relay.relay().delivered());
        assertEquals(OptinexusOutboxEvent.STATUS_DELIVERED, row.getStatus());
        assertNull(row.getLastError());
        String firstId = objectMapper.readTree(calls.stream().filter(c -> c.path().equals("/api/v1/events"))
                .toList().get(0).body()).get("event_id").asText();
        String secondId = objectMapper.readTree(calls.stream().filter(c -> c.path().equals("/api/v1/events"))
                .toList().get(1).body()).get("event_id").asText();
        assertEquals(firstId, secondId);
    }

    @Test
    public void theDelayDoublesWithEveryAttemptUpToAnHour() throws Exception {
        OptinexusOutboxEvent row = addRow("optiradar.device.offline");
        eventStatus = call -> new int[] {503};
        var relay = relay();
        List<Long> waitedMinutes = new ArrayList<>();

        for (int attempt = 0; attempt < 8; attempt++) {
            long before = eventCalls();
            long waited = 0;
            while (eventCalls() == before) {
                relay.relay();
                if (eventCalls() == before) {
                    advance(1, TimeUnit.MINUTES);
                    waited++;
                }
            }
            waitedMinutes.add(waited);
        }

        // The first attempt is immediate, then 2, 4, 8, 16, 32 and 60 minutes.
        assertEquals(List.of(0L, 2L, 4L, 8L, 16L, 32L, 60L, 60L), waitedMinutes);
        assertEquals(8, row.getAttempts());
    }

    @Test
    public void anEventTypeThatIsNotInTheCatalogYetWaitsInsteadOfFailing() throws Exception {
        OptinexusOutboxEvent row = addRow("optiradar.device.overspeed");
        eventStatus = call -> new int[] {422};
        eventBody = "{\"error\":{\"code\":\"EVENT_INVALID\"}}";
        var relay = relay();

        assertEquals(1, relay.relay().retrying());
        assertEquals(OptinexusOutboxEvent.STATUS_PENDING, row.getStatus());
        assertTrue(row.getLastError().contains("Event Catalog"));

        eventStatus = call -> new int[] {201};
        eventBody = "{\"data\":{}}";
        advance(3, TimeUnit.MINUTES);
        assertEquals(1, relay.relay().delivered());
    }

    @Test
    public void aRefusalThatRetryingCannotFixParksTheEventAtOnce() throws Exception {
        OptinexusOutboxEvent row = addRow("optiradar.device.online");
        eventStatus = call -> new int[] {403};
        eventBody = "{\"error\":{\"code\":\"EVENT_SOURCE_DENIED\"}}";
        var relay = relay();

        var result = relay.relay();

        assertEquals(1, result.failed());
        assertEquals(OptinexusOutboxEvent.STATUS_FAILED, row.getStatus());
        assertTrue(row.getLastError().contains("EVENT_SOURCE_DENIED"));
        advance(2, TimeUnit.HOURS);
        relay.relay();
        assertEquals(1, eventCalls());
    }

    @Test
    public void anEventIsParkedWhenTheAttemptsRunOut() throws Exception {
        OptinexusOutboxEvent row = addRow("optiradar.device.online");
        eventStatus = call -> new int[] {500};
        var relay = relay("http://127.0.0.1:" + server.getAddress().getPort(), 2);

        relay.relay();
        assertEquals(OptinexusOutboxEvent.STATUS_PENDING, row.getStatus());
        advance(3, TimeUnit.MINUTES);
        var result = relay.relay();

        assertEquals(1, result.failed());
        assertEquals(OptinexusOutboxEvent.STATUS_FAILED, row.getStatus());
        assertEquals(2, row.getAttempts());
    }

    @Test
    public void anExpiredTokenIsRenewedOnceAndTheEventSentAgain() throws Exception {
        OptinexusOutboxEvent row = addRow("optiradar.device.online");
        eventStatus = call -> new int[] {"Bearer token-1".equals(call.authorization()) ? 401 : 201};

        var result = relay().relay();

        assertEquals(1, result.delivered());
        assertEquals(2, tokenCalls());
        assertEquals(2, eventCalls());
        assertEquals(OptinexusOutboxEvent.STATUS_DELIVERED, row.getStatus());
    }

    @Test
    public void aFailedSignInKeepsTheEventPendingWithoutSendingIt() throws Exception {
        OptinexusOutboxEvent row = addRow("optiradar.device.online");
        tokenStatus = 401;

        var result = relay().relay();

        assertEquals(1, result.retrying());
        assertEquals(0, eventCalls());
        assertEquals(OptinexusOutboxEvent.STATUS_PENDING, row.getStatus());
        assertTrue(row.getLastError().contains("authentication failed"));
    }

    @Test
    public void whenOptiNexusIsUnreachableTheBatchStopsAfterTheFirstEvent() throws Exception {
        OptinexusOutboxEvent first = addRow("optiradar.device.online");
        OptinexusOutboxEvent second = addRow("optiradar.device.offline");
        int deadPort;
        try (var socket = new ServerSocket(0)) {
            deadPort = socket.getLocalPort();
        }

        var result = relay("http://127.0.0.1:" + deadPort, 20).relay();

        assertEquals(1, result.retrying());
        assertEquals(1, first.getAttempts());
        assertEquals(0, second.getAttempts());
        assertTrue(first.getLastError().startsWith("OptiNexus unreachable"));
        assertEquals(OptinexusOutboxEvent.STATUS_PENDING, first.getStatus());
    }

    @Test
    public void oldDeliveredEventsAreDeletedAndTheRestKept() throws Exception {
        OptinexusOutboxEvent old = addRow("optiradar.device.online");
        old.setStatus(OptinexusOutboxEvent.STATUS_DELIVERED);
        old.setDeliveredAt(new Date(START - TimeUnit.DAYS.toMillis(8)));
        OptinexusOutboxEvent recent = addRow("optiradar.device.online");
        recent.setStatus(OptinexusOutboxEvent.STATUS_DELIVERED);
        recent.setDeliveredAt(new Date(START - TimeUnit.DAYS.toMillis(2)));
        OptinexusOutboxEvent failed = addRow("optiradar.device.online");
        failed.setStatus(OptinexusOutboxEvent.STATUS_FAILED);

        relay().relay();

        List<OptinexusOutboxEvent> left = storage.getObjects(OptinexusOutboxEvent.class,
                new Request(new Columns.All()));
        assertEquals(2, left.size());
        assertTrue(left.contains(recent));
        assertTrue(left.contains(failed));
    }

    @Test
    public void isConfiguredOnlyWithAddressAndCredentials() {
        assertTrue(relay().configured());
        assertTrue(!new OptinexusEventRelay(new Config(), storage, client, objectMapper).configured());
    }

}
