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
     * Makes the tenant group the only tenant group of the user. Groups and links that do not belong to a tenant
     * are left alone.
     */
    public void link(HttpServletRequest request, User user, Group tenantGroup) throws Exception {
        Set<Long> tenantGroupIds = new HashSet<>();
        for (Group group : tenantGroups()) {
            tenantGroupIds.add(group.getId());
        }

        boolean linked = false;
        for (Permission permission : storage.getPermissions(User.class, user.getId(), Group.class, 0)) {
            long groupId = permission.getPropertyId();
            if (groupId == tenantGroup.getId()) {
                linked = true;
            } else if (tenantGroupIds.contains(groupId)) {
                storage.removePermission(permission);
                cacheManager.invalidatePermission(true, User.class, user.getId(), Group.class, groupId, false);
                actionLogger.unlink(request, user.getId(), User.class, user.getId(), Group.class, groupId);
            }
        }

        if (!linked) {
            storage.addPermission(new Permission(User.class, user.getId(), Group.class, tenantGroup.getId()));
            cacheManager.invalidatePermission(true, User.class, user.getId(), Group.class, tenantGroup.getId(), true);
            actionLogger.link(request, user.getId(), User.class, user.getId(), Group.class, tenantGroup.getId());
        }
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
