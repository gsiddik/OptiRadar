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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.model.OptinexusOutboxEvent;
import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Order;
import org.traccar.storage.query.Request;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Delivers the outbox written by {@link OptinexusEventRecorder} to OptiNexus (POST /api/v1/events).
 *
 * <p>A row only becomes DELIVERED after OptiNexus accepted it, and it is sent under its own id as {@code event_id},
 * so a retry after a timeout never creates a second event.
 *
 * <ul>
 * <li>200/201: DELIVERED.</li>
 * <li>Network error, 5xx, 408, 429, 401 and 422 EVENT_INVALID (the event type is not in the OptiNexus catalog yet):
 * stays PENDING and is tried again with growing delay (2 minutes after the first attempt, doubling up to 1 hour),
 * until the attempts run out.</li>
 * <li>Any other 4xx (payload does not match the catalog, application not assigned to the tenant, event id
 * conflict): FAILED at once. After the cause is fixed, set the row back to PENDING with attempts 0.</li>
 * </ul>
 */
@Singleton
public class OptinexusEventRelay {

    private static final Logger LOGGER = LoggerFactory.getLogger(OptinexusEventRelay.class);

    private static final String SCOPE = "event.write";
    private static final int SCAN_LIMIT = 1000;
    private static final int ERROR_LENGTH = 900;
    private static final long MAX_BACKOFF_SECONDS = 3600;
    private static final Set<Integer> RETRYABLE_CLIENT_ERRORS = Set.of(401, 408, 429);

    public record Result(int delivered, int retrying, int failed) { }

    private final Storage storage;
    private final Client client;
    private final ObjectMapper objectMapper;
    private final String baseUrl;
    private final String clientId;
    private final String clientSecret;
    private final int batchSize;
    private final int maxAttempts;
    private final int retentionDays;

    private String accessToken;
    private long accessTokenExpires;

    @Inject
    public OptinexusEventRelay(Config config, Storage storage, Client client, ObjectMapper objectMapper) {
        this.storage = storage;
        this.client = client;
        this.objectMapper = objectMapper;
        String url = config.getString(Keys.OPTINEXUS_BASE_URL);
        this.baseUrl = url != null ? url.replaceAll("/+$", "") : null;
        this.clientId = config.getString(Keys.OPTINEXUS_CLIENT_ID);
        this.clientSecret = config.getString(Keys.OPTINEXUS_CLIENT_SECRET);
        this.batchSize = config.getInteger(Keys.OPTINEXUS_EVENTS_BATCH_SIZE);
        this.maxAttempts = config.getInteger(Keys.OPTINEXUS_EVENTS_MAX_ATTEMPTS);
        this.retentionDays = config.getInteger(Keys.OPTINEXUS_EVENTS_RETENTION_DAYS);
    }

    public boolean configured() {
        return baseUrl != null && !baseUrl.isBlank()
                && clientId != null && !clientId.isBlank()
                && clientSecret != null && !clientSecret.isBlank();
    }

    protected long now() {
        return System.currentTimeMillis();
    }

    public synchronized Result relay() throws StorageException {
        int delivered = 0;
        int retrying = 0;
        int failed = 0;

        long now = now();
        List<OptinexusOutboxEvent> due = storage.getObjects(OptinexusOutboxEvent.class, new Request(
                new Columns.All(),
                new Condition.Equals("status", OptinexusOutboxEvent.STATUS_PENDING),
                new Order("id", false, SCAN_LIMIT))).stream()
                .filter(row -> isDue(row, now))
                .limit(batchSize)
                .toList();

        for (OptinexusOutboxEvent row : due) {
            row.setAttempts(row.getAttempts() + 1);
            row.setLastAttemptedAt(new Date(now()));
            save(row, "attempts", "lastAttemptedAt");

            Response response;
            try {
                response = post(row);
            } catch (ProcessingException e) {
                // OptiNexus is unreachable: stop here instead of hammering it with the rest of the batch.
                if (retryOrPark(row, "OptiNexus unreachable: " + e.getMessage())) {
                    failed++;
                } else {
                    retrying++;
                }
                break;
            } catch (Exception e) {
                if (retryOrPark(row, String.valueOf(e.getMessage()))) {
                    failed++;
                } else {
                    retrying++;
                }
                continue;
            }

            try (response) {
                int status = response.getStatus();
                String body = response.hasEntity() ? response.readEntity(String.class) : "";
                if (status == 200 || status == 201) {
                    row.setStatus(OptinexusOutboxEvent.STATUS_DELIVERED);
                    row.setDeliveredAt(new Date(now()));
                    row.setLastError(null);
                    save(row, "status", "deliveredAt", "lastError");
                    delivered++;
                } else if (status == 422 && "EVENT_INVALID".equals(errorCode(body))) {
                    if (retryOrPark(row, "OptiNexus does not know this event type yet (register it in the Event "
                            + "Catalog).")) {
                        failed++;
                    } else {
                        retrying++;
                    }
                } else if (status >= 400 && status < 500 && !RETRYABLE_CLIENT_ERRORS.contains(status)) {
                    park(row, "HTTP " + status + ": " + body);
                    failed++;
                } else if (retryOrPark(row, "HTTP " + status)) {
                    failed++;
                } else {
                    retrying++;
                }
            }
        }

        deleteOldDelivered();
        return new Result(delivered, retrying, failed);
    }

    private boolean isDue(OptinexusOutboxEvent row, long now) {
        if (row.getLastAttemptedAt() == null) {
            return true;
        }
        long seconds = Math.min(60L * (1L << Math.min(row.getAttempts(), 20)), MAX_BACKOFF_SECONDS);
        return row.getLastAttemptedAt().getTime() + TimeUnit.SECONDS.toMillis(seconds) <= now;
    }

    /**
     * @return true when the event was parked as FAILED because the attempts ran out
     */
    private boolean retryOrPark(OptinexusOutboxEvent row, String error) throws StorageException {
        if (row.getAttempts() >= maxAttempts) {
            park(row, error);
            return true;
        }
        row.setLastError(truncate(error));
        save(row, "lastError");
        return false;
    }

    private void park(OptinexusOutboxEvent row, String error) throws StorageException {
        row.setStatus(OptinexusOutboxEvent.STATUS_FAILED);
        row.setLastError(truncate(error));
        save(row, "status", "lastError");
        LOGGER.warn("OptiNexus event {} parked as failed: {}", row.getEventUuid(), row.getLastError());
    }

    private void save(OptinexusOutboxEvent row, String... columns) throws StorageException {
        storage.updateObject(row, new Request(new Columns.Include(columns), new Condition.Equals("id", row.getId())));
    }

    private void deleteOldDelivered() throws StorageException {
        if (retentionDays > 0) {
            Date cutoff = new Date(now() - TimeUnit.DAYS.toMillis(retentionDays));
            storage.removeObject(OptinexusOutboxEvent.class, new Request(new Condition.And(
                    new Condition.Equals("status", OptinexusOutboxEvent.STATUS_DELIVERED),
                    new Condition.Compare("deliveredAt", "<", cutoff))));
        }
    }

    private static String truncate(String text) {
        if (text == null) {
            return null;
        }
        return text.length() > ERROR_LENGTH ? text.substring(0, ERROR_LENGTH) : text;
    }

    private String errorCode(String body) {
        try {
            JsonNode code = objectMapper.readTree(body).path("error").path("code");
            return code.isMissingNode() ? null : code.asText();
        } catch (Exception e) {
            return null;
        }
    }

    private Response post(OptinexusOutboxEvent row) throws Exception {
        String json = objectMapper.writeValueAsString(envelope(row));
        Response response = send(json);
        if (response.getStatus() == 401) {
            response.close();
            accessToken = null;
            response = send(json);
        }
        return response;
    }

    private Response send(String json) throws Exception {
        return client.target(baseUrl + "/api/v1/events").request()
                .header("Authorization", "Bearer " + token())
                .accept(MediaType.APPLICATION_JSON)
                .post(Entity.entity(json, MediaType.APPLICATION_JSON));
    }

    Map<String, Object> envelope(OptinexusOutboxEvent row) throws Exception {
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("event_id", row.getEventUuid());
        envelope.put("event_key", row.getEventKey());
        envelope.put("event_version", "1");
        envelope.put("occurred_at", row.getOccurredAt().toInstant().toString());
        envelope.put("tenant_id", row.getTenantId());
        envelope.put("correlation_id", "device:" + row.getDeviceId());
        envelope.put("data", objectMapper.readValue(row.getPayload(), Map.class));
        return envelope;
    }

    private String token() throws Exception {
        if (accessToken != null && now() < accessTokenExpires) {
            return accessToken;
        }
        Form form = new Form()
                .param("grant_type", "client_credentials")
                .param("client_id", clientId)
                .param("client_secret", clientSecret)
                .param("scope", SCOPE);
        try (Response response = client.target(baseUrl + "/api/v1/oauth/token").request()
                .accept(MediaType.APPLICATION_JSON).post(Entity.form(form))) {
            String body = response.hasEntity() ? response.readEntity(String.class) : "";
            JsonNode json = objectMapper.readTree(body);
            if (response.getStatus() != 200 || json.path("access_token").asText("").isEmpty()) {
                throw new IllegalStateException("OptiNexus authentication failed (HTTP " + response.getStatus() + ")");
            }
            long lifetime = json.path("expires_in").asLong(3600);
            accessToken = json.path("access_token").asText();
            accessTokenExpires = now() + TimeUnit.SECONDS.toMillis(Math.max(lifetime - 60, 30));
            return accessToken;
        }
    }

}
