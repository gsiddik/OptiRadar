package org.traccar.governance;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Prints OptiRadar's catalog as the OptiNexus manifest (version 2.0), the file
 * {@code php artisan ecosystem:import-manifest optiradar <file>} and {@code POST /applications/{id}/manifest} read.
 *
 * <p>Run: {@code java -cp tracker-server.jar:lib/* org.traccar.governance.ManifestExporter > manifest.json}, or ask a
 * running server: {@code GET /api/governance/manifest} (local administrator only).</p>
 */
public final class ManifestExporter {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    private ManifestExporter() {
    }

    public static Map<String, Object> manifest() {
        Map<String, Object> application = new LinkedHashMap<>();
        application.put("application_code", Catalog.APPLICATION_CODE);
        application.put("name", "OptiRadar");
        application.put("description", "GPS telematics and vehicle tracking.");

        List<Map<String, Object>> capabilities = new ArrayList<>();
        for (Catalog.Capability capability : Catalog.capabilities()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("code", capability.code());
            row.put("type", capability.type());
            row.put("name", capability.name());
            row.put("description", capability.description());
            row.put("sort_order", capability.sortOrder());
            row.put("parent_code", capability.parent());
            capabilities.add(row);
        }

        List<Map<String, Object>> permissions = new ArrayList<>();
        for (Catalog.Permission permission : Catalog.permissions()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("permission_key", permission.key());
            row.put("name", permission.name());
            row.put("description", permission.description());
            row.put("capability_code", permission.capability());
            row.put("delegable", permission.delegable());
            permissions.add(row);
        }

        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("manifest_version", Catalog.MANIFEST_VERSION);
        manifest.put("revision", Catalog.REVISION);
        manifest.put("application", application);
        manifest.put("capabilities", capabilities);
        manifest.put("permissions", permissions);
        return manifest;
    }

    public static String json() throws JsonProcessingException {
        return MAPPER.writeValueAsString(manifest()) + "\n";
    }

    public static void main(String[] args) throws JsonProcessingException {
        System.out.print(json());
    }

}
