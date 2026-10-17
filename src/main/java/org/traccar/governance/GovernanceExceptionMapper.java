package org.traccar.governance;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import java.util.UUID;

/**
 * Turns a {@link GovernanceException} raised inside a resource (not only in the request filter) into the same JSON
 * answer, so the web app sees one shape whatever raised it.
 */
public class GovernanceExceptionMapper implements ExceptionMapper<GovernanceException> {

    private static final Logger LOGGER = LoggerFactory.getLogger(GovernanceExceptionMapper.class);

    @Context
    private ContainerRequestContext requestContext;

    @Override
    public Response toResponse(GovernanceException exception) {
        String correlation = requestContext != null
                ? GovernanceRequestFilter.correlationId(requestContext)
                : UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        LOGGER.info("Access refused code={} permission={} ref={}", exception.getCode(), exception.getPermission(),
                correlation);
        return GovernanceRequestFilter.response(exception, correlation);
    }

}
