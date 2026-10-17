package org.traccar.api.resource;

import org.traccar.api.BaseResource;
import org.traccar.governance.Catalog;
import org.traccar.governance.GovernanceService;
import org.traccar.governance.Governed;
import org.traccar.governance.ManifestExporter;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
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

}
