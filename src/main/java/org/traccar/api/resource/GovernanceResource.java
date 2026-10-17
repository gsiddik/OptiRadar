package org.traccar.api.resource;

import org.traccar.api.BaseResource;
import org.traccar.governance.Catalog;
import org.traccar.governance.GovernanceException;
import org.traccar.governance.GovernanceService;
import org.traccar.governance.Governed;
import org.traccar.governance.ManifestExporter;

import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What the web app needs to draw itself from the access OptiNexus granted, and the catalog for OptiNexus. The web app
 * only represents these answers; every route enforces them again.
 */
@Governed(access = Governed.Access.SELF)
@Path("governance")
@Produces(MediaType.APPLICATION_JSON)
public class GovernanceResource extends BaseResource {

    @Inject
    private GovernanceService governance;

    @Context
    private HttpServletRequest request;

    /**
     * The catalog as the OptiNexus manifest (version 2.0), for the operator who imports it.
     */
    @Governed(access = Governed.Access.OPERATOR)
    @Path("manifest")
    @GET
    public Map<String, Object> manifest() {
        return ManifestExporter.manifest();
    }

    /**
     * The signed-in user's effective permissions and entitled modules, with the time they are valid until. With
     * governance off {@code governed} is false and the web app shows what native rights allow, as before.
     */
    @Path("context")
    @GET
    public GovernanceService.Context context() {
        if (!governance.enabled()) {
            return new GovernanceService.Context(false, "native", null, List.of(), List.of(), true, 0, 0,
                    Catalog.REVISION);
        }
        return governance.context(governance.principal(getUserId()));
    }

    /**
     * The other products the signed-in user may open in the same tenant (OptiNexus {@code product-context}), for the
     * product switcher. {@code fresh=true} asks OptiNexus again (the switcher does when it opens and before it leaves
     * for another product). When OptiNexus says the access ended, the browser session ends and this answers 401
     * {@code governance_access_revoked}. When OptiNexus cannot answer: 503 and no products.
     */
    @Path("products")
    @GET
    public Map<String, Object> products(@QueryParam("fresh") @DefaultValue("false") boolean fresh) {
        Map<String, Object> body = new LinkedHashMap<>();
        if (!governance.enabled()) {
            body.put("governed", false);
            body.put("products", List.of());
            return body;
        }
        GovernanceService.Products result;
        try {
            result = governance.products(governance.principal(getUserId()), fresh);
        } catch (GovernanceException e) {
            if (e.endsSessions()) {
                try {
                    HttpSession session = request.getSession(false);
                    if (session != null) {
                        session.invalidate();
                    }
                } catch (RuntimeException ignored) {
                    // an in-process call has no browser session
                }
            }
            throw e;
        }
        body.put("governed", true);
        body.put("tenant", result.tenant());
        body.put("products", result.products());
        body.put("expiresAt", result.expiresAt());
        body.put("ttlSeconds", result.ttlSeconds());
        return body;
    }

}
