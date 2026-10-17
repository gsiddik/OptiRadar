package org.traccar.governance;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * What OptiRadar publishes to OptiNexus: its modules and features (capabilities that a tenant buys) and the atomic
 * permissions a role can hold. This is the single definition: the manifest sent to OptiNexus, the enforcement on
 * the REST API, the WebSocket and the background jobs, and the delegable set all read it.
 *
 * <p>Permission keys carry the OptiNexus application code ({@code optiradar.}) as OptiNexus requires. A permission is
 * only <em>delegable</em> (an Admin Tenant may put it into a custom role) when the rationale in
 * {@code docs/governance.md} says so; the default is {@code false}. Changing anything here means a new
 * {@link #REVISION}; {@code CatalogTest} fails until the committed manifest file matches.</p>
 */
public final class Catalog {

    public static final String APPLICATION_CODE = "optiradar";
    public static final String MANIFEST_VERSION = "2.0";
    public static final String REVISION = "2026.10.17-1";

    /**
     * A module or feature a tenant is entitled to (OptiNexus capability).
     */
    public record Capability(String code, String type, String name, String description, String parent, int sortOrder) {
    }

    /**
     * An atomic permission, always inside one capability.
     */
    public record Permission(
            String key, String name, String description, String capability, boolean delegable) {
    }

    // Permission keys used by the enforcement code.
    public static final String LIVE_VIEW = "optiradar.live.view";
    public static final String POSITIONS_VIEW = "optiradar.positions.view";
    public static final String POSITIONS_DELETE = "optiradar.positions.delete";
    public static final String POSITIONS_EXPORT = "optiradar.positions.export";
    public static final String DEVICES_VIEW = "optiradar.devices.view";
    public static final String DEVICES_MANAGE = "optiradar.devices.manage";
    public static final String DEVICES_ODOMETER_SET = "optiradar.devices.odometer.set";
    public static final String GROUPS_VIEW = "optiradar.groups.view";
    public static final String GROUPS_MANAGE = "optiradar.groups.manage";
    public static final String SHARING_MANAGE = "optiradar.sharing.manage";
    public static final String STREAM_VIEW = "optiradar.stream.view";
    public static final String GEOFENCES_VIEW = "optiradar.geofences.view";
    public static final String GEOFENCES_MANAGE = "optiradar.geofences.manage";
    public static final String REPORTS_VIEW = "optiradar.reports.view";
    public static final String REPORTS_EXPORT = "optiradar.reports.export";
    public static final String REPORTS_SCHEDULE = "optiradar.reports.schedule";
    public static final String COMMANDS_VIEW = "optiradar.commands.view";
    public static final String COMMANDS_SEND = "optiradar.commands.send";
    public static final String COMMANDS_MANAGE = "optiradar.commands.manage";
    public static final String EVENTS_VIEW = "optiradar.events.view";
    public static final String NOTIFICATIONS_VIEW = "optiradar.notifications.view";
    public static final String NOTIFICATIONS_MANAGE = "optiradar.notifications.manage";
    public static final String NOTIFICATIONS_SEND = "optiradar.notifications.send";
    public static final String DRIVERS_VIEW = "optiradar.drivers.view";
    public static final String DRIVERS_MANAGE = "optiradar.drivers.manage";
    public static final String MAINTENANCE_VIEW = "optiradar.maintenance.view";
    public static final String MAINTENANCE_MANAGE = "optiradar.maintenance.manage";
    public static final String CALENDARS_VIEW = "optiradar.calendars.view";
    public static final String CALENDARS_MANAGE = "optiradar.calendars.manage";
    public static final String ATTRIBUTES_VIEW = "optiradar.attributes.view";
    public static final String ATTRIBUTES_MANAGE = "optiradar.attributes.manage";
    public static final String ORDERS_VIEW = "optiradar.orders.view";
    public static final String ORDERS_MANAGE = "optiradar.orders.manage";
    public static final String ACCESS_MANAGE = "optiradar.access.manage";

    private static final List<Capability> CAPABILITIES = new ArrayList<>();
    private static final List<Permission> PERMISSIONS = new ArrayList<>();
    private static final Map<String, Permission> BY_KEY = new LinkedHashMap<>();
    private static final Map<String, Capability> CAPABILITY_BY_CODE = new LinkedHashMap<>();

    private static int order;

    static {
        module("optiradar.tracking", "Live tracking and history", "Map, live positions and route history.");
        feature("optiradar.tracking", "optiradar.tracking.live", "Live map",
                "Live positions and device status on the map.");
        feature("optiradar.tracking", "optiradar.tracking.history", "Route history and replay",
                "Stored positions of a device over a period, and the replay of a route.");
        feature("optiradar.tracking", "optiradar.tracking.export", "Position export",
                "Download stored positions as KML, KMZ, CSV or GPX.");

        module("optiradar.devices", "Devices and groups", "The tenant's tracked assets and how they are grouped.");
        feature("optiradar.devices", "optiradar.devices.registry", "Device and group registry",
                "List, create, edit and remove devices and groups of the tenant.");
        feature("optiradar.devices", "optiradar.devices.odometer", "Odometer and engine hours",
                "Overwrite the accumulated distance and engine hours of a device.");
        feature("optiradar.devices", "optiradar.devices.sharing", "Share links",
                "Time-limited public links to a device or group location.");
        feature("optiradar.devices", "optiradar.devices.video", "Video streams",
                "Live video streams of devices that have a camera.");

        module("optiradar.geofencing", "Geofences", "Zones that raise events when an asset enters or leaves.");
        feature("optiradar.geofencing", "optiradar.geofencing.zones", "Geofence zones",
                "List, draw, edit and remove geofences.");

        module("optiradar.reporting", "Reports", "Analysis of trips, stops, routes, events and summaries.");
        feature("optiradar.reporting", "optiradar.reporting.standard", "Reports on screen",
                "Run and read reports in the application.");
        feature("optiradar.reporting", "optiradar.reporting.export", "Report export and e-mail",
                "Download reports as spreadsheets or send them by e-mail.");
        feature("optiradar.reporting", "optiradar.reporting.scheduled", "Scheduled reports",
                "Reports that are prepared and announced by e-mail on a calendar.");

        module("optiradar.commands", "Device commands", "Instructions sent to the tracker in the vehicle.");
        feature("optiradar.commands", "optiradar.commands.send", "Send commands",
                "Send a command to a device and see which commands it supports.");
        feature("optiradar.commands", "optiradar.commands.saved", "Saved commands",
                "Maintain the list of saved commands.");

        module("optiradar.alerts", "Events and notifications", "What happened and who is told about it.");
        feature("optiradar.alerts", "optiradar.alerts.events", "Event history",
                "Read events such as alarms, overspeed and geofence crossings.");
        feature("optiradar.alerts", "optiradar.alerts.notifications", "Notification rules",
                "Rules that tell users about events by e-mail, push or other channels.");
        feature("optiradar.alerts", "optiradar.alerts.announcements", "Announcements",
                "Send a message to users and test the notification channels.");

        module("optiradar.operations", "Drivers, maintenance and automation",
                "People, service schedules and rules around the vehicles.");
        feature("optiradar.operations", "optiradar.operations.drivers", "Drivers",
                "Driver registry and driver assignment.");
        feature("optiradar.operations", "optiradar.operations.maintenance", "Maintenance",
                "Service schedules driven by distance, hours or time.");
        feature("optiradar.operations", "optiradar.operations.calendars", "Calendars",
                "Calendars that limit when notifications and reports apply.");
        feature("optiradar.operations", "optiradar.operations.attributes", "Computed attributes",
                "Expressions that derive values from incoming positions.");
        feature("optiradar.operations", "optiradar.operations.orders", "Orders",
                "Work orders for drivers and devices.");

        module("optiradar.access", "Access management",
                "Users and roles of the tenant inside OptiRadar, kept in OptiNexus.");
        feature("optiradar.access", "optiradar.access.users", "Users and roles",
                "Create users and custom roles through OptiNexus delegation.");

        permission(LIVE_VIEW, "View live positions",
                "Receive live positions, device status and the latest position of each device.",
                "optiradar.tracking.live", true);
        permission(POSITIONS_VIEW, "View position history",
                "Read the stored positions of a device over a period and replay a route.",
                "optiradar.tracking.history", true);
        permission(POSITIONS_DELETE, "Delete stored positions",
                "Permanently delete stored positions. Destroys history.", "optiradar.tracking.history", false);
        permission(POSITIONS_EXPORT, "Export positions",
                "Download positions as KML, KMZ, CSV or GPX.", "optiradar.tracking.export", true);

        permission(DEVICES_VIEW, "View devices", "List and open devices.", "optiradar.devices.registry", true);
        permission(DEVICES_MANAGE, "Manage devices",
                "Create, edit and remove devices and their images.", "optiradar.devices.registry", true);
        permission(GROUPS_VIEW, "View groups", "List and open groups.", "optiradar.devices.registry", true);
        permission(GROUPS_MANAGE, "Manage groups",
                "Create, edit and remove groups below the tenant group.", "optiradar.devices.registry", true);
        permission(DEVICES_ODOMETER_SET, "Set odometer and engine hours",
                "Overwrite accumulated distance and engine hours, which other products may read.",
                "optiradar.devices.odometer", false);
        permission(SHARING_MANAGE, "Create share links",
                "Create public links that show a device location without signing in.",
                "optiradar.devices.sharing", false);
        permission(STREAM_VIEW, "View video streams", "Watch live video of a device.",
                "optiradar.devices.video", true);

        permission(GEOFENCES_VIEW, "View geofences", "List and open geofences.", "optiradar.geofencing.zones", true);
        permission(GEOFENCES_MANAGE, "Manage geofences",
                "Create, edit and remove geofences and attach them to devices.", "optiradar.geofencing.zones", true);

        permission(REPORTS_VIEW, "Run reports", "Run and read reports in the application.",
                "optiradar.reporting.standard", true);
        permission(REPORTS_EXPORT, "Export reports", "Download reports as spreadsheets or e-mail them.",
                "optiradar.reporting.export", true);
        permission(REPORTS_SCHEDULE, "Schedule reports", "Create and run scheduled reports.",
                "optiradar.reporting.scheduled", true);

        permission(COMMANDS_VIEW, "View commands", "See saved commands and the commands a device supports.",
                "optiradar.commands.send", true);
        permission(COMMANDS_SEND, "Send commands",
                "Send a command to a device, for example an engine cut-off. Acts on the vehicle.",
                "optiradar.commands.send", false);
        permission(COMMANDS_MANAGE, "Manage saved commands", "Create, edit and remove saved commands.",
                "optiradar.commands.saved", false);

        permission(EVENTS_VIEW, "View events",
                "Read events and receive notifications that describe them.", "optiradar.alerts.events", true);
        permission(NOTIFICATIONS_VIEW, "View notification rules", "List notification rules and channels.",
                "optiradar.alerts.notifications", true);
        permission(NOTIFICATIONS_MANAGE, "Manage notification rules",
                "Create, edit and remove notification rules and attach them to devices.",
                "optiradar.alerts.notifications", true);
        permission(NOTIFICATIONS_SEND, "Send announcements",
                "Send a message to other users and test channels. Reaches people outside the caller.",
                "optiradar.alerts.announcements", false);

        permission(DRIVERS_VIEW, "View drivers", "List drivers.", "optiradar.operations.drivers", true);
        permission(DRIVERS_MANAGE, "Manage drivers", "Create, edit and remove drivers and assign them.",
                "optiradar.operations.drivers", true);
        permission(MAINTENANCE_VIEW, "View maintenance", "List maintenance schedules.",
                "optiradar.operations.maintenance", true);
        permission(MAINTENANCE_MANAGE, "Manage maintenance", "Create, edit and remove maintenance schedules.",
                "optiradar.operations.maintenance", true);
        permission(CALENDARS_VIEW, "View calendars", "List calendars.", "optiradar.operations.calendars", true);
        permission(CALENDARS_MANAGE, "Manage calendars", "Create, edit and remove calendars.",
                "optiradar.operations.calendars", true);
        permission(ATTRIBUTES_VIEW, "View computed attributes", "List computed attributes.",
                "optiradar.operations.attributes", true);
        permission(ATTRIBUTES_MANAGE, "Manage computed attributes",
                "Create, edit, test and remove expressions that run on the server for every position.",
                "optiradar.operations.attributes", false);
        permission(ORDERS_VIEW, "View orders", "List orders.", "optiradar.operations.orders", true);
        permission(ORDERS_MANAGE, "Manage orders", "Create, edit and remove orders.",
                "optiradar.operations.orders", true);

        permission(ACCESS_MANAGE, "Manage users and roles",
                "Open the users and roles pages; OptiNexus still requires the Admin Tenant flag for every change.",
                "optiradar.access.users", false);
    }

    private Catalog() {
    }

    private static void module(String code, String name, String description) {
        add(new Capability(code, "MODULE", name, description, null, ++order * 10));
    }

    private static void feature(String parent, String code, String name, String description) {
        add(new Capability(code, "FEATURE", name, description, parent, ++order * 10));
    }

    private static void add(Capability capability) {
        CAPABILITIES.add(capability);
        CAPABILITY_BY_CODE.put(capability.code(), capability);
    }

    private static void permission(String key, String name, String description, String capability, boolean delegable) {
        if (!CAPABILITY_BY_CODE.containsKey(capability)) {
            throw new IllegalStateException("Unknown capability " + capability);
        }
        Permission permission = new Permission(key, name, description, capability, delegable);
        if (BY_KEY.put(key, permission) != null) {
            throw new IllegalStateException("Duplicate permission " + key);
        }
        PERMISSIONS.add(permission);
    }

    public static List<Capability> capabilities() {
        return List.copyOf(CAPABILITIES);
    }

    public static List<Permission> permissions() {
        return List.copyOf(PERMISSIONS);
    }

    public static Optional<Permission> permission(String key) {
        return Optional.ofNullable(BY_KEY.get(key));
    }

    public static Optional<Capability> capability(String code) {
        return Optional.ofNullable(CAPABILITY_BY_CODE.get(code));
    }

    /**
     * The capability a permission belongs to, or null for a key that is not in the catalog.
     */
    public static String capabilityOf(String permissionKey) {
        Permission permission = BY_KEY.get(permissionKey);
        return permission != null ? permission.capability() : null;
    }

    /**
     * The module above a feature, or null when the code is a module (or unknown).
     */
    public static String moduleOf(String capabilityCode) {
        Capability capability = CAPABILITY_BY_CODE.get(capabilityCode);
        return capability != null ? capability.parent() : null;
    }

}
