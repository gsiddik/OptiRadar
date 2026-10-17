package org.traccar.governance;

import org.traccar.api.security.ServiceAccountUser;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.database.OpenIdApps;
import org.traccar.database.OpenIdLifecycle;
import org.traccar.model.BaseModel;
import org.traccar.model.Device;
import org.traccar.model.Group;
import org.traccar.model.GroupedModel;
import org.traccar.model.Notification;
import org.traccar.model.User;
import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.List;
import java.util.Objects;

/**
 * Protects what ties an account to its tenant, and what lets one object act beyond its own permission, when a tenant
 * user (not a native administrator) writes objects.
 *
 * <ul>
 * <li>The attributes the sign-in keeps on a user (session cut-off, deactivation, logout address, application list)
 * cannot be changed by the user: the stored values are kept.</li>
 * <li>The group attribute that names the tenant cannot be set, changed or removed by a tenant user: otherwise a
 * tenant could claim another tenant's identifier.</li>
 * <li>With governance enabled, devices and groups stay below a group the user can reach (never at the top level,
 * where no tenant owns them), and a notification that sends a command needs the permission to send commands.</li>
 * </ul>
 */
@Singleton
public class GovernanceGuard {

    private static final List<String> USER_RESERVED = List.of(
            OpenIdLifecycle.SESSIONS_NOT_BEFORE, OpenIdLifecycle.DEACTIVATED, OpenIdLifecycle.LOGOUT_URL,
            OpenIdApps.ATTRIBUTE);

    private final Storage storage;
    private final GovernanceService governance;
    private final String tenantAttribute;

    @Inject
    public GovernanceGuard(Config config, Storage storage, GovernanceService governance) {
        this.storage = storage;
        this.governance = governance;
        this.tenantAttribute = config.getString(Keys.OPENID_TENANT_GROUP_ATTRIBUTE);
    }

    /**
     * Checks (and for user attributes, repairs) an object a user is about to store. {@code before} is the stored
     * object, or null for an addition.
     */
    public void check(long actorId, BaseModel entity, boolean addition) throws StorageException {
        if (actorId == ServiceAccountUser.ID) {
            return;
        }
        boolean relevant = entity instanceof User || entity instanceof Group || entity instanceof Device
                || entity instanceof Notification;
        if (!relevant) {
            return;
        }
        User actor = storage.getObject(User.class, new Request(
                new Columns.Include("id", "administrator"), new Condition.Equals("id", actorId)));
        if (actor == null || actor.getAdministrator()) {
            return;
        }
        if (entity instanceof User user && !addition) {
            keepUserAttributes(user);
        }
        if (entity instanceof Group group) {
            checkTenantAttribute(group, addition);
        }
        if (governance.enabled()) {
            GovernedPrincipal principal = governance.principal(actorId);
            if (principal.kind() == GovernedPrincipal.Kind.CENTRAL) {
                checkPlacement(entity);
                if (entity instanceof Notification notification) {
                    checkNotification(principal, notification);
                }
            }
        }
    }

    private void keepUserAttributes(User after) throws StorageException {
        User before = storage.getObject(User.class, new Request(
                new Columns.All(), new Condition.Equals("id", after.getId())));
        if (before == null) {
            return;
        }
        for (String key : USER_RESERVED) {
            Object stored = before.getAttributes().get(key);
            if (stored == null) {
                after.getAttributes().remove(key);
            } else {
                after.getAttributes().put(key, stored);
            }
        }
    }

    private void checkTenantAttribute(Group after, boolean addition) throws StorageException {
        if (tenantAttribute == null) {
            return;
        }
        Object wanted = after.getAttributes().get(tenantAttribute);
        Object stored = null;
        if (!addition) {
            Group before = storage.getObject(Group.class, new Request(
                    new Columns.All(), new Condition.Equals("id", after.getId())));
            stored = before != null ? before.getAttributes().get(tenantAttribute) : null;
        }
        if (!Objects.equals(wanted, stored)) {
            throw new GovernanceException(403, GovernanceException.RESERVED_ATTRIBUTE,
                    "The tenant attribute of a group is set by an administrator", null);
        }
    }

    private void checkPlacement(BaseModel entity) {
        if ((entity instanceof Device || entity instanceof Group) && ((GroupedModel) entity).getGroupId() <= 0) {
            throw new GovernanceException(400, GovernanceException.INVALID_PLACEMENT,
                    "Devices and groups of a tenant must be placed in one of its groups", null);
        }
    }

    private void checkNotification(GovernedPrincipal principal, Notification notification) {
        if (notification.getCommandId() > 0 || notification.getNotificatorsTypes().contains("command")) {
            governance.require(principal, List.of(Catalog.COMMANDS_SEND));
        }
    }

}
