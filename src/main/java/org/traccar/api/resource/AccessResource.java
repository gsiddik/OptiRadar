package org.traccar.api.resource;

import com.fasterxml.jackson.databind.JsonNode;
import org.traccar.api.BaseResource;
import org.traccar.governance.Catalog;
import org.traccar.governance.DelegationException;
import org.traccar.governance.DelegationService;
import org.traccar.governance.GovernanceRequestFilter;
import org.traccar.governance.Governed;
import org.traccar.helper.LogAction;

import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Users and custom roles of the signed-in user's tenant, managed through the OptiNexus delegation API. OptiRadar keeps
 * no copy: every call is forwarded with OptiRadar's service account on behalf of the signed-in Admin Tenant, and the
 * answers are OptiNexus' own (snake_case) documents. The tenant and the acting user come from the account's identity
 * link, never from the request.
 */
@Governed(value = Catalog.ACCESS_MANAGE)
@Path("access")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AccessResource extends BaseResource {

    @Inject
    private DelegationService delegation;

    @Inject
    private LogAction actionLogger;

    @Context
    private HttpServletRequest request;

    @Context
    private ContainerRequestContext requestContext;

    @Path("catalog")
    @GET
    public Response catalog() {
        return respond(delegation.catalog(getUserId()));
    }

    @Path("users")
    @GET
    public Response users(@QueryParam("search") String search, @QueryParam("perPage") Integer perPage) {
        return respond(delegation.listUsers(getUserId(), search, perPage));
    }

    @Path("users")
    @POST
    public Response addUser(JsonNode body) {
        return audited("user.add", body != null ? body.path("email").asText("") : "",
                () -> delegation.addUser(getUserId(), body));
    }

    @Path("users/{user}/roles")
    @PUT
    public Response setUserRoles(@PathParam("user") String user, JsonNode body) {
        return audited("user.roles", user, () -> delegation.setUserRoles(getUserId(), user, body));
    }

    @Path("users/{user}")
    @DELETE
    public Response removeUser(@PathParam("user") String user) {
        return audited("user.remove", user, () -> delegation.removeUser(getUserId(), user));
    }

    @Path("roles")
    @POST
    public Response createRole(JsonNode body) {
        return audited("role.create", body != null ? body.path("name").asText("") : "",
                () -> delegation.createRole(getUserId(), body));
    }

    @Path("roles/{role}")
    @PUT
    public Response updateRole(@PathParam("role") String role, JsonNode body) {
        return audited("role.update", role, () -> delegation.updateRole(getUserId(), role, body));
    }

    @Path("roles/{role}")
    @DELETE
    public Response deleteRole(@PathParam("role") String role) {
        return audited("role.delete", role, () -> delegation.deleteRole(getUserId(), role));
    }

    private Response audited(String operation, String target, Supplier<DelegationService.Result> action) {
        String correlation = GovernanceRequestFilter.correlationId(requestContext);
        try {
            DelegationService.Result result = action.get();
            actionLogger.delegation(request, getUserId(), operation, clip(target), "ok", correlation);
            return respond(result);
        } catch (DelegationException e) {
            actionLogger.delegation(request, getUserId(), operation, clip(target), e.getCode(), correlation);
            throw e;
        }
    }

    private static String clip(String value) {
        return value != null && value.length() > 120 ? value.substring(0, 120) : value;
    }

    private Response respond(DelegationService.Result result) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("data", result.data());
        if (result.meta() != null && !result.meta().isMissingNode() && !result.meta().isNull()) {
            body.put("meta", result.meta());
        }
        return Response.status(result.status()).entity(body).header("Cache-Control", "no-store").build();
    }

}
