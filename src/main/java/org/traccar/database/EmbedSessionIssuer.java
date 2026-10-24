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

import org.traccar.api.signature.TokenManager;
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
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Issues the short-lived token behind an embedded map (OptiNexus embed sessions). Each call creates a new temporary,
 * read-only user that can see the devices of one tenant group only, with no commands and no reports, and a token that
 * ends with the user. Expired embed users are removed on the next call, so they do not pile up.
 */
@Singleton
public class EmbedSessionIssuer {

    static final String EMAIL_PREFIX = "embed:";
    static final long MIN_TTL_SECONDS = 60;
    public static final long MAX_TTL_SECONDS = 900;

    private final Storage storage;
    private final CacheManager cacheManager;
    private final OpenIdTenantLinker tenantLinker;
    private final TokenManager tokenManager;

    @Inject
    public EmbedSessionIssuer(
            Storage storage, CacheManager cacheManager, OpenIdTenantLinker tenantLinker, TokenManager tokenManager) {
        this.storage = storage;
        this.cacheManager = cacheManager;
        this.tenantLinker = tenantLinker;
        this.tokenManager = tokenManager;
    }

    public record Session(String token, Date expiration) {
    }

    public Session issue(String tenantId, long ttlSeconds) throws Exception {

        long ttl = Math.max(MIN_TTL_SECONDS, Math.min(ttlSeconds, MAX_TTL_SECONDS));
        Group group = tenantLinker.findGroup(tenantId);

        purgeExpired();

        Date expiration = new Date(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(ttl));
        User user = new User();
        user.setName("OptiNexus embed");
        user.setEmail(EMAIL_PREFIX + group.getId() + ":" + UUID.randomUUID());
        user.setTemporary(true);
        user.setReadonly(true);
        user.setLimitCommands(true);
        user.setDisableReports(true);
        user.setExpirationTime(expiration);
        user.setId(storage.addObject(user, new Request(new Columns.Exclude("id"))));

        storage.addPermission(new Permission(User.class, user.getId(), Group.class, group.getId()));
        cacheManager.invalidatePermission(true, User.class, user.getId(), Group.class, group.getId(), true);

        return new Session(tokenManager.generateToken(user.getId(), expiration), expiration);
    }

    private void purgeExpired() throws StorageException {
        long now = System.currentTimeMillis();
        for (User user : storage.getObjects(User.class, new Request(new Columns.All()))) {
            if (user.getTemporary() && user.getEmail() != null && user.getEmail().startsWith(EMAIL_PREFIX)
                    && user.getExpirationTime() != null && user.getExpirationTime().getTime() < now) {
                storage.removeObject(User.class, new Request(new Condition.Equals("id", user.getId())));
            }
        }
    }

}
