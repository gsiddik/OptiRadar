package org.traccar.governance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CatalogTest {

    private static final Pattern PERMISSION_KEY = Pattern.compile("^[a-z][a-z0-9_-]*(\\.[A-Za-z0-9_-]+)+$");
    private static final Pattern CAPABILITY_CODE = Pattern.compile("^[A-Za-z0-9_.:-]+$");

    /**
     * The only permissions an Admin Tenant may put into a custom role. Widening this set is a decision: change it here,
     * in {@link Catalog} and in docs/governance.md together.
     */
    private static final Set<String> DELEGABLE = Set.of(
            "optiradar.live.view", "optiradar.positions.view", "optiradar.positions.export",
            "optiradar.devices.view", "optiradar.devices.manage", "optiradar.groups.view",
            "optiradar.groups.manage", "optiradar.stream.view",
            "optiradar.geofences.view", "optiradar.geofences.manage",
            "optiradar.reports.view", "optiradar.reports.export", "optiradar.reports.schedule",
            "optiradar.commands.view", "optiradar.events.view",
            "optiradar.notifications.view", "optiradar.notifications.manage",
            "optiradar.drivers.view", "optiradar.drivers.manage",
            "optiradar.maintenance.view", "optiradar.maintenance.manage",
            "optiradar.calendars.view", "optiradar.calendars.manage",
            "optiradar.attributes.view", "optiradar.orders.view", "optiradar.orders.manage");

    @Test
    public void everyPermissionFollowsTheNexusImportRules() {
        Set<String> keys = new HashSet<>();
        for (Catalog.Permission permission : Catalog.permissions()) {
            assertTrue(PERMISSION_KEY.matcher(permission.key()).matches(), permission.key());
            assertTrue(permission.key().startsWith(Catalog.APPLICATION_CODE + "."), permission.key());
            assertFalse(permission.key().startsWith("cgo."), permission.key());
            assertTrue(keys.add(permission.key()), "duplicate " + permission.key());
            assertNotNull(permission.name());
            assertTrue(permission.name().length() <= 255);
            assertTrue(permission.description().length() <= 1000);
            assertTrue(Catalog.capability(permission.capability()).isPresent(), permission.key());
        }
        assertTrue(Catalog.permissions().size() <= 2000);
    }

    @Test
    public void capabilitiesFormAValidHierarchy() {
        Set<String> codes = new HashSet<>();
        for (Catalog.Capability capability : Catalog.capabilities()) {
            assertTrue(CAPABILITY_CODE.matcher(capability.code()).matches(), capability.code());
            assertTrue(capability.code().startsWith(Catalog.APPLICATION_CODE + "."), capability.code());
            assertTrue(codes.add(capability.code()), "duplicate " + capability.code());
            if (capability.type().equals("MODULE")) {
                assertEquals(null, capability.parent(), capability.code());
            } else {
                assertEquals("FEATURE", capability.type());
                Catalog.Capability parent = Catalog.capability(capability.parent()).orElseThrow();
                assertEquals("MODULE", parent.type(), capability.code());
            }
        }
        assertTrue(Catalog.capabilities().size() <= 500);
    }

    @Test
    public void everyModuleHasFeaturesAndEveryFeatureHasPermissions() {
        Set<String> featuresWithPermissions = Catalog.permissions().stream()
                .map(Catalog.Permission::capability).collect(Collectors.toSet());
        for (Catalog.Capability capability : Catalog.capabilities()) {
            if (capability.type().equals("MODULE")) {
                assertTrue(Catalog.capabilities().stream().anyMatch(c -> capability.code().equals(c.parent())),
                        "module without features: " + capability.code());
            } else {
                assertTrue(featuresWithPermissions.contains(capability.code()),
                        "feature without permissions: " + capability.code());
            }
        }
    }

    @Test
    public void delegableSetIsExplicitAndDefaultsToFalse() {
        Set<String> delegable = Catalog.permissions().stream()
                .filter(Catalog.Permission::delegable).map(Catalog.Permission::key).collect(Collectors.toSet());
        assertEquals(DELEGABLE, delegable);
        // Anything that acts on the vehicle, destroys history, reaches other people or manages access is not delegable.
        for (String key : List.of(
                Catalog.COMMANDS_SEND, Catalog.COMMANDS_MANAGE, Catalog.POSITIONS_DELETE,
                Catalog.DEVICES_ODOMETER_SET, Catalog.SHARING_MANAGE, Catalog.NOTIFICATIONS_SEND,
                Catalog.ATTRIBUTES_MANAGE, Catalog.ACCESS_MANAGE)) {
            assertFalse(Catalog.permission(key).orElseThrow().delegable(), key);
        }
    }

    @Test
    public void committedManifestIsCurrent() throws IOException {
        Path file = Path.of("docs", "governance", "optiradar-manifest.json");
        assertTrue(Files.isRegularFile(file), "missing " + file);
        String committed = Files.readString(file, StandardCharsets.UTF_8);
        assertEquals(ManifestExporter.json(), committed,
                "Regenerate docs/governance/optiradar-manifest.json (java ... ManifestExporter) and bump "
                        + "Catalog.REVISION when the catalog changes");
    }

    @Test
    public void manifestHasTheShapeOptiNexusImports() throws IOException {
        JsonNode manifest = new ObjectMapper().readTree(ManifestExporter.json());
        assertEquals("2.0", manifest.get("manifest_version").asText());
        assertEquals(Catalog.REVISION, manifest.get("revision").asText());
        assertEquals("optiradar", manifest.get("application").get("application_code").asText());
        assertEquals(Catalog.permissions().size(), manifest.get("permissions").size());
        for (JsonNode permission : manifest.get("permissions")) {
            assertTrue(permission.get("delegable").isBoolean());
            assertTrue(permission.hasNonNull("capability_code"));
        }
        assertEquals(Catalog.capabilities().size(), manifest.get("capabilities").size());
    }

}
