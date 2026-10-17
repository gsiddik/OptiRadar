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
import org.traccar.model.Group;
import org.traccar.model.ObjectOperation;
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
import jakarta.servlet.http.HttpSession;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.LongConsumer;

/**
 * What happens to an OptiRadar account when the OpenID provider says the user logged out elsewhere or lost access.
 *
 * <ul>
 * <li>The account is found by the provider's stable identity (issuer + subject, see {@link OpenIdIdentities}), never by
 * email: an address that changed or was given to somebody else must not end or switch off the wrong account.</li>
 * <li>Every event ends the user's web sessions: the time is stored in a user attribute and a session that began
 * earlier is no longer accepted.</li>
 * <li>Access lost for the whole user also disables the account, so no other way in works either. The account is
 * marked, and only an account marked here is switched on again by the next successful sign-in through the provider
 * (an administrator's own disabling stays).</li>
 * <li>Access lost for one tenant only removes the user from that tenant's group.</li>
 * </ul>
 */
@Singleton
public class OpenIdLifecycle {

    private static final Logger LOGGER = LoggerFactory.getLogger(OpenIdLifecycle.class);

    public static final String SESSIONS_NOT_BEFORE = "optinexusSessionsNotBefore";
    public static final String DEACTIVATED = "optinexusDeactivated";
    public static final String LOGOUT_URL = "optinexusLogoutUrl";

    private final Storage storage;
    private final CacheManager cacheManager;
    private final OpenIdIdentities identities;
    private final String tenantAttribute;
    private final List<LongConsumer> listeners = new CopyOnWriteArrayList<>();

    @Inject
    public OpenIdLifecycle(
            Config config, Storage storage, CacheManager cacheManager, OpenIdIdentities identities) {
        this.storage = storage;
        this.cacheManager = cacheManager;
        this.identities = identities;
        this.tenantAttribute = config.getString(Keys.OPENID_TENANT_GROUP_ATTRIBUTE);
    }

    /**
     * Tells {@code listener} the id of every user whose sessions or tenant scope changed here, so what was decided
     * about the user earlier (for example cached grants) is dropped.
     */
    public void addListener(LongConsumer listener) {
        listeners.add(listener);
    }

    private void changed(User user) {
        for (LongConsumer listener : listeners) {
            listener.accept(user.getId());
        }
    }

    /**
     * True when the user's sessions were ended after this session began.
     */
    public static boolean isSessionRevoked(User user, HttpSession session) {
        long notBefore = user.getLong(SESSIONS_NOT_BEFORE);
        return notBefore > 0 && session.getCreationTime() < notBefore;
    }

    /**
     * Switches an account on again if, and only if, an earlier event from the provider switched it off.
     *
     * @return true if the user was changed (the caller stores "disabled" and "attributes")
     */
    public static boolean reactivate(User user) {
        if (user.getDisabled() && user.getBoolean(DEACTIVATED)) {
            user.setDisabled(false);
            user.removeAttribute(DEACTIVATED);
            return true;
        }
        return false;
    }

    public void apply(OpenIdLogoutTokens.Event event) throws Exception {
        User user = identities.findUser(event.issuer(), event.subject());
        if (user == null) {
            // Nobody signed in with this identity here: there is no session or account of it to touch.
            LOGGER.info("OpenID provider event for an identity that is not linked to any account");
            return;
        }

        user.set(SESSIONS_NOT_BEFORE, System.currentTimeMillis());
        Columns columns = new Columns.Include("attributes");

        if (event.accessRevoked()) {
            if (event.tenantScope()) {
                leaveTenant(user, event.tenantId());
            } else if (!user.getDisabled()) {
                user.setDisabled(true);
                user.set(DEACTIVATED, true);
                columns = new Columns.Include("attributes", "disabled");
            }
        }

        storage.updateObject(user, new Request(columns, new Condition.Equals("id", user.getId())));
        cacheManager.invalidateObject(true, User.class, user.getId(), ObjectOperation.UPDATE);
        changed(user);
        LOGGER.info("OpenID provider ended sessions of user {}{}", user.getId(),
                event.accessRevoked() ? " and revoked access" : "");
    }

    /**
     * Ends every web session of the user that began before now, for example because the user is now active in
     * another tenant.
     */
    public void endSessions(User user) throws Exception {
        user.set(SESSIONS_NOT_BEFORE, System.currentTimeMillis());
        storage.updateObject(user, new Request(
                new Columns.Include("attributes"), new Condition.Equals("id", user.getId())));
        cacheManager.invalidateObject(true, User.class, user.getId(), ObjectOperation.UPDATE);
        changed(user);
    }

    public void rememberLogoutUrl(User user, String url) throws StorageException {
        if (url == null || url.equals(user.getAttributes().get(LOGOUT_URL))) {
            return;
        }
        user.set(LOGOUT_URL, url);
        storage.updateObject(user, new Request(
                new Columns.Include("attributes"), new Condition.Equals("id", user.getId())));
    }

    private void leaveTenant(User user, String tenantId) throws Exception {
        if (tenantId == null || tenantAttribute == null) {
            return;
        }
        String wanted = tenantId.trim().toLowerCase(Locale.ROOT);
        for (Group group : storage.getObjects(Group.class, new Request(new Columns.All()))) {
            Object value = group.getAttributes().get(tenantAttribute);
            if (value != null && wanted.equals(value.toString().trim().toLowerCase(Locale.ROOT))) {
                for (Permission permission : storage.getPermissions(User.class, user.getId(), Group.class, 0)) {
                    if (permission.getPropertyId() == group.getId()) {
                        storage.removePermission(permission);
                        cacheManager.invalidatePermission(
                                true, User.class, user.getId(), Group.class, group.getId(), false);
                    }
                }
            }
        }
    }

}
