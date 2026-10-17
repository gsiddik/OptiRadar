package org.traccar.governance;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Answers an access-management failure as JSON {@code {error, message, nexusCode, details, correlationId}}. A mapper is
 * needed because the resource error handler replaces the entity of any exception that carries one.
 */
public class DelegationExceptionMapper implements ExceptionMapper<DelegationException> {

    private static final Logger LOGGER = LoggerFactory.getLogger(DelegationExceptionMapper.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Context
    private ContainerRequestContext requestContext;

    @Override
    public Response toResponse(DelegationException exception) {
        String correlation = requestContext != null
                ? GovernanceRequestFilter.correlationId(requestContext)
                : UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        return response(exception, correlation);
    }

    static Response response(DelegationException e, String correlation) {
        LOGGER.info("Access management refused code={} nexus={} ref={}", e.getCode(), e.getNexusCode(), correlation);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", e.getCode());
        body.put("message", e.getMessage());
        if (e.getNexusCode() != null) {
            body.put("nexusCode", e.getNexusCode());
        }
        if (e.getDetails() != null) {
            body.put("details", e.getDetails());
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

}
