package org.traccar.governance;

import org.junit.jupiter.api.Test;
import org.traccar.api.BaseResource;

import jakarta.annotation.security.PermitAll;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HEAD;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import java.io.File;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The route table of the REST API against the access catalog. If a route is added without an answer in
 * {@link Governed}, tenant users would be refused it at run time ({@code governance_route_unmapped}); this test makes
 * the build fail first.
 */
public class GovernanceCoverageTest {

    /** Permissions that are enforced outside a {@link Governed} annotation (rules and the WebSocket). */
    private static final Set<String> ENFORCED_ELSEWHERE = Set.of(Catalog.LIVE_VIEW, Catalog.POSITIONS_VIEW);

    /** GET routes a read-only integration account (the OptiNexus telematics connector) may call. */
    private static final Set<String> INTEGRATION_ROUTES = Set.of(
            "DeviceResource.get", "DeviceResource.getSingle", "GroupResource.get", "GroupResource.getSingle",
            "PositionResource.getJson");

    private record Route(Class<?> type, Method method, String verb) {
        String name() {
            return type.getSimpleName() + "." + method.getName();
        }
    }

    private static String verbOf(Method method) {
        if (method.isAnnotationPresent(GET.class)) {
            return "GET";
        } else if (method.isAnnotationPresent(POST.class)) {
            return "POST";
        } else if (method.isAnnotationPresent(PUT.class)) {
            return "PUT";
        } else if (method.isAnnotationPresent(DELETE.class)) {
            return "DELETE";
        } else if (method.isAnnotationPresent(HEAD.class)) {
            return "HEAD";
        }
        return null;
    }

    /**
     * Every class of the resource package on the whole class path (test and main output directories both contain that
     * package, so the first directory alone is not enough).
     */
    private static List<Class<?>> resourceClasses() throws Exception {
        String packageName = "org.traccar.api.resource";
        String path = packageName.replace('.', '/');
        Set<String> names = new TreeSet<>();
        for (URL url : Collections.list(BaseResource.class.getClassLoader().getResources(path))) {
            if (url.getProtocol().equals("file")) {
                File[] files = new File(url.toURI()).listFiles();
                for (File file : files != null ? files : new File[0]) {
                    if (file.getName().endsWith(".class") && !file.getName().contains("$")) {
                        names.add(file.getName().substring(0, file.getName().length() - 6));
                    }
                }
            } else if (url.getProtocol().equals("jar")) {
                String file = URLDecoder.decode(url.getFile(), StandardCharsets.UTF_8);
                try (JarFile jar = new JarFile(file.substring(5, file.indexOf('!')))) {
                    jar.stream().map(JarEntry::getName)
                            .filter(name -> name.startsWith(path + "/") && name.endsWith(".class")
                                    && !name.contains("$"))
                            .forEach(name -> names.add(name.substring(path.length() + 1, name.length() - 6)));
                }
            }
        }
        List<Class<?>> classes = new ArrayList<>();
        for (String name : names) {
            Class<?> type = Class.forName(packageName + "." + name);
            if (BaseResource.class.isAssignableFrom(type)) {
                classes.add(type);
            }
        }
        return classes;
    }

    private static List<Route> routes() throws Exception {
        List<Route> routes = new ArrayList<>();
        for (Class<?> type : resourceClasses()) {
            if (!type.isAnnotationPresent(Path.class)) {
                continue;
            }
            for (Method method : type.getMethods()) {
                String verb = verbOf(method);
                if (verb != null) {
                    routes.add(new Route(type, method, verb));
                }
            }
        }
        return routes;
    }

    @Test
    public void routesAreFound() throws Exception {
        assertTrue(routes().size() > 80, "the scan must see the whole API, saw " + routes().size());
    }

    @Test
    public void everyRouteHasAnAccessAnswerOrIsOpen() throws Exception {
        List<String> missing = new ArrayList<>();
        for (Route route : routes()) {
            if (route.method().isAnnotationPresent(PermitAll.class)) {
                continue;
            }
            if (GovernanceRequestFilter.requirement(route.method(), route.type(), route.verb()) == null) {
                missing.add(route.verb() + " " + route.name());
            }
        }
        assertEquals(List.of(), missing, "routes without @Governed: add the permission they need");
    }

    @Test
    public void everyPermissionNamedByARouteIsInTheCatalog() throws Exception {
        List<String> unknown = new ArrayList<>();
        for (Route route : routes()) {
            var requirement = GovernanceRequestFilter.requirement(route.method(), route.type(), route.verb());
            if (requirement == null) {
                continue;
            }
            for (String permission : requirement.permissions()) {
                if (Catalog.permission(permission).isEmpty()) {
                    unknown.add(route.name() + " -> " + permission);
                }
            }
            if (requirement.access() == Governed.Access.DYNAMIC
                    && !Set.of("positions.get", "permissions.link").contains(requirement.rule())) {
                unknown.add(route.name() + " -> rule " + requirement.rule());
            }
        }
        assertEquals(List.of(), unknown);
    }

    @Test
    public void everyCatalogPermissionIsEnforcedSomewhere() throws Exception {
        Set<String> used = new TreeSet<>(ENFORCED_ELSEWHERE);
        for (Route route : routes()) {
            var requirement = GovernanceRequestFilter.requirement(route.method(), route.type(), route.verb());
            if (requirement != null) {
                used.addAll(requirement.permissions());
            }
        }
        // The link rule resolves the permission of what is attached; these are the ones only it names
        used.add(Catalog.COMMANDS_SEND);
        Set<String> unused = new TreeSet<>();
        for (Catalog.Permission permission : Catalog.permissions()) {
            if (!used.contains(permission.key())) {
                unused.add(permission.key());
            }
        }
        assertEquals(Set.of(), unused, "a permission in the manifest that nothing enforces is a broken promise");
    }

    @Test
    public void onlyTheTelematicsRoutesAreOpenToIntegrationAccounts() throws Exception {
        Set<String> open = new TreeSet<>();
        for (Route route : routes()) {
            var requirement = GovernanceRequestFilter.requirement(route.method(), route.type(), route.verb());
            if (requirement != null && requirement.integration() && route.verb().equals("GET")) {
                open.add(route.name());
            }
        }
        assertEquals(new TreeSet<>(INTEGRATION_ROUTES), open);
    }

    @Test
    public void routesThatChangeStateNeverAllowIntegrationAccounts() throws Exception {
        for (Route route : routes()) {
            var requirement = GovernanceRequestFilter.requirement(route.method(), route.type(), route.verb());
            if (requirement != null && requirement.integration()) {
                assertTrue(route.verb().equals("GET") || route.verb().equals("HEAD"),
                        route.verb() + " " + route.name() + " is marked for integrations but is not a read");
            }
        }
    }

    @Test
    public void tenantUsersNeverReachWhatIsReservedForAdministrators() throws Exception {
        Set<String> operatorOnly = new TreeSet<>();
        for (Route route : routes()) {
            var requirement = GovernanceRequestFilter.requirement(route.method(), route.type(), route.verb());
            if (requirement != null && requirement.access() == Governed.Access.OPERATOR) {
                operatorOnly.add(route.name());
            }
        }
        for (String expected : List.of("AuditResource.get", "StatisticsResource.get", "UserResource.get",
                "UserResource.remove", "PermissionsResource.get")) {
            assertTrue(operatorOnly.contains(expected), expected + " must stay operator-only: " + operatorOnly);
        }
    }

}
