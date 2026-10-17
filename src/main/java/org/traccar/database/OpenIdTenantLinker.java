/*
 * Copyright 2026 Anton Tananaev (anton@traccar.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.database;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.helper.LogAction;
import org.traccar.model.Device;
import org.traccar.model.Group;
import org.traccar.model.Permission;
import org.traccar.model.User;
import org.traccar.session.cache.CacheManager;
import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.servlet.http.HttpServletRequest;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Ties OpenID Connect users to their tenant. A tenant is a group carrying the identifier in a configured
 * attribute; after a login the user is linked to the group of the tenant they signed in to and to no other
 * tenant group, so one tenant's users never see another tenant's devices.
 */
@Singleton
public class OpenIdTenantLinker {

    private static final Logger LOGGER = LoggerFactory.getLogger(OpenIdTenantLinker.class);

    private final Storage storage;
    private final CacheManager cacheManager;
    private final LogAction actionLogger;
    private final String attribute;

    @Inject
    public OpenIdTenantLinker(Config config, Storage storage, CacheManager cacheManager, LogAction actionLogger) {
        this.storage = storage;
        this.cacheManager = cacheManager;
        this.actionLogger = actionLogger;
        this.attribute = config.getString(Keys.OPENID_TENANT_GROUP_ATTRIBUTE);
    }

    /**
     * The one group that belongs to the tenant.
     *
     * @throws GeneralSecurityException if the tenant is missing, has no group, or has more than one
     */
    public Group findGroup(String tenantId) throws StorageException, GeneralSecurityException {
        if (tenantId == null || tenantId.isBlank()) {
            throw new GeneralSecurityException("The OpenID provider did not name a tenant");
        }
        String wanted = tenantId.trim().toLowerCase(Locale.ROOT);
        List<Group> matches = tenantGroups().stream()
                .filter(group -> wanted.equals(tenantOf(group)))
                .toList();
        if (matches.isEmpty()) {
            throw new GeneralSecurityException("Your organization is not set up in this system");
        }
        if (matches.size() > 1) {
            LOGGER.error("More than one group carries {}={}", attribute, tenantId);
            throw new GeneralSecurityException("Your organization is not set up correctly in this system");
        }
        return matches.get(0);
    }

    /**
     * Makes the tenant the only tenant of the user: the tenant group is linked, and every link of the user to a group
     * (or to a device in a group) that belongs to another tenant is removed, so signing in to one tenant never
     * leaves the data of another tenant in reach. Groups and devices that belong to no tenant are left alone.
     *
     * @return true when the user's tenant scope changed (first link, or something of another tenant was removed);
     *         the caller then ends the user's other sessions, so no open session silently gets the new scope
     */
    public boolean link(HttpServletRequest request, User user, Group tenantGroup) throws Exception {
        Map<Long, Group> groups = new HashMap<>();
        for (Group group : storage.getObjects(Group.class, new Request(new Columns.All()))) {
            groups.put(group.getId(), group);
        }
        String wanted = tenantOf(tenantGroup);

        boolean linked = false;
        boolean changed = false;
        for (Permission permission : storage.getPermissions(User.class, user.getId(), Group.class, 0)) {
            long groupId = permission.getPropertyId();
            if (groupId == tenantGroup.getId()) {
                linked = true;
            } else if (belongsToOtherTenant(groups.get(groupId), groups, wanted)) {
                storage.removePermission(permission);
                cacheManager.invalidatePermission(true, User.class, user.getId(), Group.class, groupId, false);
                actionLogger.unlink(request, user.getId(), User.class, user.getId(), Group.class, groupId);
                changed = true;
            }
        }

        for (Permission permission : storage.getPermissions(User.class, user.getId(), Device.class, 0)) {
            Device device = storage.getObject(Device.class, new Request(
                    new Columns.Include("id", "groupId"), new Condition.Equals("id", permission.getPropertyId())));
            if (device != null && device.getGroupId() > 0
                    && belongsToOtherTenant(groups.get(device.getGroupId()), groups, wanted)) {
                storage.removePermission(permission);
                cacheManager.invalidatePermission(
                        true, User.class, user.getId(), Device.class, permission.getPropertyId(), false);
                actionLogger.unlink(
                        request, user.getId(), User.class, user.getId(), Device.class, permission.getPropertyId());
                changed = true;
            }
        }

        if (!linked) {
            storage.addPermission(new Permission(User.class, user.getId(), Group.class, tenantGroup.getId()));
            cacheManager.invalidatePermission(true, User.class, user.getId(), Group.class, tenantGroup.getId(), true);
            actionLogger.link(request, user.getId(), User.class, user.getId(), Group.class, tenantGroup.getId());
            changed = true;
        }
        return changed;
    }

    /**
     * True when the group, or a group above it, is a tenant group of a tenant other than {@code wanted}.
     */
    private boolean belongsToOtherTenant(Group group, Map<Long, Group> groups, String wanted) {
        Set<Long> seen = new HashSet<>();
        while (group != null && seen.add(group.getId())) {
            String tenant = tenantOf(group);
            if (tenant != null) {
                return !tenant.equals(wanted);
            }
            group = group.getGroupId() > 0 ? groups.get(group.getGroupId()) : null;
        }
        return false;
    }

    /**
     * Remembers the applications the provider lets the user open, for the web app's application menu. Only the
     * user's attributes are written, and only when the list changed.
     */
    public void rememberApps(User user, List<Map<String, String>> apps) throws StorageException {
        Object current = user.getAttributes().get(OpenIdApps.ATTRIBUTE);
        if (apps.isEmpty() ? current == null : apps.equals(current)) {
            return;
        }
        if (apps.isEmpty()) {
            user.getAttributes().remove(OpenIdApps.ATTRIBUTE);
        } else {
            user.getAttributes().put(OpenIdApps.ATTRIBUTE, apps);
        }
        storage.updateObject(user, new Request(
                new Columns.Include("attributes"), new Condition.Equals("id", user.getId())));
    }

    private List<Group> tenantGroups() throws StorageException {
        return storage.getObjects(Group.class, new Request(new Columns.All())).stream()
                .filter(group -> tenantOf(group) != null)
                .toList();
    }

    private String tenantOf(Group group) {
        Object value = group.getAttributes().get(attribute);
        if (value == null || value.toString().isBlank()) {
            return null;
        }
        return value.toString().trim().toLowerCase(Locale.ROOT);
    }
}
