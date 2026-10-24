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

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Asks OptiNexus whether a tenant's plan includes an OptiRadar feature (POST /api/v1/entitlements/check).
 *
 * <p>An answer is reused for {@code optinexus.entitlements.ttl} seconds. If OptiNexus cannot be reached the last
 * answer is used however old it is, so a short outage does not switch features off; with no answer at all the feature
 * is refused.
 */
@Singleton
public class OptinexusEntitlements {

    private static final Logger LOGGER = LoggerFactory.getLogger(OptinexusEntitlements.class);

    private static final String SCOPE = "entitlement.check";

    private record Answer(boolean allowed, long fetchedAt) { }

    private final Client client;
    private final ObjectMapper objectMapper;
    private final boolean enforce;
    private final String baseUrl;
    private final String clientId;
    private final String clientSecret;
    private final String applicationCode;
    private final long ttlMillis;

    private final Map<String, Answer> answers = new ConcurrentHashMap<>();

    private String accessToken;
    private long accessTokenExpires;

    @Inject
    public OptinexusEntitlements(Config config, Client client, ObjectMapper objectMapper) {
        this.client = client;
        this.objectMapper = objectMapper;
        this.enforce = config.getBoolean(Keys.OPTINEXUS_ENTITLEMENTS_ENFORCE);
        String url = config.getString(Keys.OPTINEXUS_BASE_URL);
        this.baseUrl = url != null ? url.replaceAll("/+$", "") : null;
        this.clientId = config.getString(Keys.OPTINEXUS_CLIENT_ID);
        this.clientSecret = config.getString(Keys.OPTINEXUS_CLIENT_SECRET);
        this.applicationCode = "optiradar";
        this.ttlMillis = TimeUnit.SECONDS.toMillis(config.getLong(Keys.OPTINEXUS_ENTITLEMENTS_TTL));
    }

    public boolean enforced() {
        return enforce;
    }

    protected long now() {
        return System.currentTimeMillis();
    }

    /**
     * True when the tenant's plan includes the feature (an OptiNexus capability code such as "trip_reports").
     */
    public boolean allows(String tenantId, String feature) {
        String key = tenantId + "/" + feature;
        Answer cached = answers.get(key);
        if (cached != null && now() - cached.fetchedAt() < ttlMillis) {
            return cached.allowed();
        }
        try {
            boolean allowed = ask(tenantId, feature);
            answers.put(key, new Answer(allowed, now()));
            return allowed;
        } catch (Exception e) {
            LOGGER.warn("OptiNexus entitlement check failed for {}: {}", feature, e.getMessage());
            return cached != null && cached.allowed();
        }
    }

    private boolean ask(String tenantId, String feature) throws Exception {
        if (baseUrl == null || baseUrl.isBlank() || clientId == null || clientSecret == null) {
            throw new IllegalStateException("OptiNexus is not configured");
        }
        Map<String, String> body = new LinkedHashMap<>();
        body.put("tenant_id", tenantId);
        body.put("application_code", applicationCode);
        body.put("entitlement_key", feature);
        String json = objectMapper.writeValueAsString(body);

        Response response = send(json);
        if (response.getStatus() == 401) {
            response.close();
            accessToken = null;
            response = send(json);
        }
        try (Response answer = response) {
            String text = answer.hasEntity() ? answer.readEntity(String.class) : "";
            if (answer.getStatus() != 200) {
                throw new IllegalStateException("OptiNexus answered HTTP " + answer.getStatus());
            }
            JsonNode allowed = objectMapper.readTree(text).path("data").path("allowed");
            if (!allowed.isBoolean()) {
                throw new IllegalStateException("OptiNexus gave no answer");
            }
            return allowed.asBoolean();
        }
    }

    private Response send(String json) throws Exception {
        return client.target(baseUrl + "/api/v1/entitlements/check").request()
                .header("Authorization", "Bearer " + token())
                .accept(MediaType.APPLICATION_JSON)
                .post(Entity.entity(json, MediaType.APPLICATION_JSON));
    }

    private synchronized String token() throws Exception {
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
