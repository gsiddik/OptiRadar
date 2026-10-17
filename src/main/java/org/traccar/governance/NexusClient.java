package org.traccar.governance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.glassfish.jersey.client.ClientProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.config.Config;
import org.traccar.config.Keys;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Server-to-server calls to OptiNexus with the OptiRadar service account (OAuth2 client credentials). Every call has a
 * connect and a read timeout, nothing is retried here (the callers decide), and the browser never sees these calls.
 *
 * <ul>
 * <li>A 2xx answer returns the {@code data} node of the OptiNexus envelope.</li>
 * <li>A refusal that OptiNexus decided (4xx other than 401, 408, 429) throws {@link RejectedException} with the
 * stable error code, so the caller can map it.</li>
 * <li>Everything else (no connection, timeout, 5xx, 429, 408, a token that is refused, an answer that is not the
 * envelope) throws {@link UnavailableException}: the caller must treat access as not decided, never as allowed.</li>
 * </ul>
 */
@Singleton
public class NexusClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(NexusClient.class);

    /**
     * OptiNexus did not give an answer (or the service account is not accepted).
     */
    public static class UnavailableException extends Exception {

        private final int retryAfterSeconds;

        public UnavailableException(String message, int retryAfterSeconds, Throwable cause) {
            super(message, cause);
            this.retryAfterSeconds = retryAfterSeconds;
        }

        public int getRetryAfterSeconds() {
            return retryAfterSeconds;
        }
    }

    /**
     * OptiNexus answered and refused the request.
     */
    public static class RejectedException extends Exception {

        private final int status;
        private final String code;
        private final transient JsonNode details;

        public RejectedException(int status, String code, String message, JsonNode details) {
            super(message);
            this.status = status;
            this.code = code;
            this.details = details;
        }

        public int getStatus() {
            return status;
        }

        public String getCode() {
            return code;
        }

        public JsonNode getDetails() {
            return details;
        }
    }

    private static final int DEFAULT_RETRY_AFTER = 5;

    private final ObjectMapper objectMapper;
    private final String baseUrl;
    private final String clientId;
    private final String clientSecret;
    private final Client client;
    private final Map<String, Token> tokens = new HashMap<>();

    private record Token(String value, long expires) {
    }

    @Inject
    public NexusClient(Config config, ClientBuilder clientBuilder, ObjectMapper objectMapper) {
        this(config, clientBuilder
                .property(ClientProperties.CONNECT_TIMEOUT, config.getInteger(Keys.GOVERNANCE_CONNECT_TIMEOUT))
                .property(ClientProperties.READ_TIMEOUT, config.getInteger(Keys.GOVERNANCE_READ_TIMEOUT))
                .build(), objectMapper);
    }

    public NexusClient(Config config, Client client, ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.client = client;
        String url = config.getString(Keys.OPTINEXUS_BASE_URL);
        this.baseUrl = url != null ? url.trim().replaceAll("/+$", "") : null;
        this.clientId = config.getString(Keys.OPTINEXUS_CLIENT_ID);
        this.clientSecret = config.getString(Keys.OPTINEXUS_CLIENT_SECRET);
    }

    public boolean configured() {
        return baseUrl != null && !baseUrl.isBlank()
                && clientId != null && !clientId.isBlank()
                && clientSecret != null && !clientSecret.isBlank();
    }

    protected long now() {
        return System.currentTimeMillis();
    }

    public JsonNode get(String scope, String path) throws UnavailableException, RejectedException {
        return call("GET", scope, path, null);
    }

    public JsonNode post(String scope, String path, Object body) throws UnavailableException, RejectedException {
        return call("POST", scope, path, body);
    }

    public JsonNode put(String scope, String path, Object body) throws UnavailableException, RejectedException {
        return call("PUT", scope, path, body);
    }

    public JsonNode delete(String scope, String path) throws UnavailableException, RejectedException {
        return call("DELETE", scope, path, null);
    }

    private JsonNode call(String method, String scope, String path, Object body)
            throws UnavailableException, RejectedException {
        if (!configured()) {
            throw new UnavailableException("OptiNexus is not configured", 60, null);
        }
        String json;
        try {
            json = body != null ? objectMapper.writeValueAsString(body) : null;
        } catch (Exception e) {
            throw new IllegalArgumentException("Request body cannot be written", e);
        }

        for (int attempt = 0; ; attempt++) {
            Response response = send(method, scope, path, json);
            try (response) {
                int status = response.getStatus();
                String text = response.hasEntity() ? response.readEntity(String.class) : "";
                if (status == 401 && attempt == 0) {
                    forget(scope);
                    continue;
                }
                return interpret(status, text, response.getHeaderString("Retry-After"));
            }
        }
    }

    private Response send(String method, String scope, String path, String json) throws UnavailableException {
        String token = token(scope);
        try {
            WebTarget target = client.target(baseUrl + path);
            Invocation.Builder request = target.request(MediaType.APPLICATION_JSON)
                    .header("Authorization", "Bearer " + token);
            if (json != null) {
                return request.build(method, Entity.entity(json, MediaType.APPLICATION_JSON)).invoke();
            }
            return request.build(method).invoke();
        } catch (ProcessingException e) {
            throw new UnavailableException("OptiNexus cannot be reached", DEFAULT_RETRY_AFTER, e);
        }
    }

    private JsonNode interpret(int status, String text, String retryAfter)
            throws UnavailableException, RejectedException {
        JsonNode root = null;
        try {
            root = text.isEmpty() ? null : objectMapper.readTree(text);
        } catch (Exception e) {
            LOGGER.debug("OptiNexus answer is not JSON (HTTP {})", status);
        }
        if (status >= 200 && status < 300) {
            if (root == null || !root.path("success").asBoolean(false)) {
                throw new UnavailableException("OptiNexus gave an unexpected answer", DEFAULT_RETRY_AFTER, null);
            }
            return root.path("data");
        }
        if (status == 401 || status == 408 || status == 429 || status >= 500) {
            int wait = DEFAULT_RETRY_AFTER;
            if (retryAfter != null) {
                try {
                    wait = Math.max(1, Math.min(300, Integer.parseInt(retryAfter.trim())));
                } catch (NumberFormatException ignored) {
                    wait = DEFAULT_RETRY_AFTER;
                }
            }
            throw new UnavailableException("OptiNexus answered HTTP " + status, wait, null);
        }
        JsonNode error = root != null ? root.path("error") : null;
        String code = error != null && error.hasNonNull("code") ? error.get("code").asText() : "HTTP_" + status;
        String message = error != null && error.hasNonNull("message") ? error.get("message").asText() : "Refused";
        throw new RejectedException(status, code, message, error != null ? error.path("details") : null);
    }

    private synchronized void forget(String scope) {
        tokens.remove(scope);
    }

    private synchronized String token(String scope) throws UnavailableException {
        Token cached = tokens.get(scope);
        if (cached != null && now() < cached.expires()) {
            return cached.value();
        }
        Form form = new Form()
                .param("grant_type", "client_credentials")
                .param("client_id", clientId)
                .param("client_secret", clientSecret)
                .param("scope", scope);
        try (Response response = client.target(baseUrl + "/api/v1/oauth/token").request(MediaType.APPLICATION_JSON)
                .post(Entity.form(form))) {
            String text = response.hasEntity() ? response.readEntity(String.class) : "";
            JsonNode json = text.isEmpty() ? null : objectMapper.readTree(text);
            if (response.getStatus() != 200 || json == null || json.path("access_token").asText("").isEmpty()) {
                // The secret is never logged; the status is enough to tell a wrong secret from an outage.
                LOGGER.warn("OptiNexus refused the service account token request (HTTP {})", response.getStatus());
                throw new UnavailableException("OptiNexus authentication failed", 30, null);
            }
            long lifetime = json.path("expires_in").asLong(3600);
            Token token = new Token(json.path("access_token").asText(),
                    now() + TimeUnit.SECONDS.toMillis(Math.max(lifetime - 60, 30)));
            tokens.put(scope, token);
            return token.value();
        } catch (ProcessingException e) {
            throw new UnavailableException("OptiNexus cannot be reached", DEFAULT_RETRY_AFTER, e);
        } catch (UnavailableException e) {
            throw e;
        } catch (Exception e) {
            throw new UnavailableException("OptiNexus gave an unexpected answer", DEFAULT_RETRY_AFTER, e);
        }
    }

}
