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
import org.traccar.helper.model.UserUtil;
import org.traccar.model.OpenIdIdentity;
import org.traccar.model.Server;
import org.traccar.model.User;
import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.servlet.http.HttpServletRequest;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.Locale;

/**
 * Who an OpenID sign-in is. An account is found by the provider's stable identifier (issuer + subject); the email is
 * only copied in as a profile attribute and can change or be given to someone else.
 *
 * <ul>
 * <li>A known identity signs in to the account it is linked to, whatever its email is now.</li>
 * <li>An unknown identity with a verified email may take over an existing account of that email once, when
 * openid.legacyEmailLinking allows it and the account is not linked to another identity of the provider yet; the
 * link is recorded and audited. An account already linked to a different identity is never handed over.</li>
 * <li>Otherwise a new account is created (if registration allows) and linked.</li>
 * </ul>
 * Uniqueness of (issuer, subject) and of (user, issuer) is enforced by the database, so two logins at the same time
 * cannot create two links.
 */
@Singleton
public class OpenIdIdentities {

    private static final Logger LOGGER = LoggerFactory.getLogger(OpenIdIdentities.class);

    /**
     * What the provider vouched for.
     */
    public record Claims(String issuer, String subject, String email, boolean emailVerified) {
    }

    private final Config config;
    private final Storage storage;
    private final LogAction actionLogger;
    private final boolean legacyEmailLinking;
    private final boolean allowRegistration;

    @Inject
    public OpenIdIdentities(Config config, Storage storage, LogAction actionLogger) {
        this.config = config;
        this.storage = storage;
        this.actionLogger = actionLogger;
        this.legacyEmailLinking = config.getBoolean(Keys.OPENID_LEGACY_EMAIL_LINKING);
        this.allowRegistration = config.getBoolean(Keys.OPENID_ALLOW_REGISTRATION);
    }

    public OpenIdIdentity find(String issuer, String subject) throws StorageException {
        if (issuer == null || subject == null) {
            return null;
        }
        return storage.getObject(OpenIdIdentity.class, new Request(
                new Columns.All(),
                new Condition.And(new Condition.Equals("issuer", issuer), new Condition.Equals("subject", subject))));
    }

    /**
     * The OpenID identity an account belongs to (the one that signed in last when several issuers were used), or null
     * when the account was never signed in through the provider.
     */
    public OpenIdIdentity findForUser(long userId) throws StorageException {
        OpenIdIdentity latest = null;
        for (OpenIdIdentity identity : storage.getObjects(OpenIdIdentity.class, new Request(
                new Columns.All(), new Condition.Equals("userId", userId)))) {
            if (latest == null || latest.getLastLoginAt() == null
                    || identity.getLastLoginAt() != null && identity.getLastLoginAt().after(latest.getLastLoginAt())) {
                latest = identity;
            }
        }
        return latest;
    }

    private OpenIdIdentity findForUser(long userId, String issuer) throws StorageException {
        return storage.getObject(OpenIdIdentity.class, new Request(
                new Columns.All(),
                new Condition.And(new Condition.Equals("userId", userId), new Condition.Equals("issuer", issuer))));
    }

    /**
     * The account of an identity, or null when the identity was never linked.
     */
    public User findUser(String issuer, String subject) throws StorageException {
        OpenIdIdentity identity = find(issuer, subject);
        if (identity == null) {
            return null;
        }
        return storage.getObject(User.class, new Request(
                new Columns.All(), new Condition.Equals("id", identity.getUserId())));
    }

    /**
     * Same lookup the password sign-in uses, so an account is the same account for both.
     */
    protected User findUserByEmail(String lowerCaseEmail) throws StorageException {
        return storage.getObject(User.class, new Request(
                new Columns.All(), new Condition.Equals("LOWER(email)", lowerCaseEmail)));
    }

    /**
     * Finds, links or creates the account for a verified OpenID sign-in. The account is not checked for being
     * disabled; the caller does that after this has switched on accounts the provider itself had switched off.
     *
     * @throws GeneralSecurityException if the sign-in must not reach any account (conflict, unverified email,
     *                                  registration closed, linking closed)
     */
    public User resolve(HttpServletRequest request, Claims claims, String name, Boolean administrator)
            throws StorageException, GeneralSecurityException {

        OpenIdIdentity identity = find(claims.issuer(), claims.subject());

        if (identity != null) {
            User user = storage.getObject(User.class, new Request(
                    new Columns.All(), new Condition.Equals("id", identity.getUserId())));
            if (user == null) {
                throw new GeneralSecurityException("The account of this OpenID identity no longer exists");
            }
            reactivateAndRefresh(user, name, administrator);
            refreshProfileEmail(user, claims);
            identity.setLastLoginAt(new Date());
            identity.setEmail(claims.email());
            storage.updateObject(identity, new Request(
                    new Columns.Include("lastLoginAt", "email"), new Condition.Equals("id", identity.getId())));
            return user;
        }

        if (claims.email() == null || claims.email().isBlank()) {
            throw new GeneralSecurityException("The OpenID provider did not return an email address");
        }
        if (!claims.emailVerified()) {
            throw new GeneralSecurityException("Your email address is not verified");
        }
        String email = claims.email().trim().toLowerCase(Locale.ROOT);

        User user = findUserByEmail(email);
        if (user != null) {
            if (!legacyEmailLinking) {
                throw new GeneralSecurityException("This account is not linked to your OpenID identity");
            }
            if (findForUser(user.getId(), claims.issuer()) != null) {
                // The account belongs to somebody else at the provider (the address changed hands or was reused).
                actionLogger.openIdConflict(request, user.getId());
                LOGGER.warn("OpenID sign-in refused: account {} is linked to another identity of {}",
                        user.getId(), claims.issuer());
                throw new GeneralSecurityException("This account is linked to a different OpenID identity");
            }
            reactivateAndRefresh(user, name, administrator);
            link(request, user, claims, OpenIdIdentity.VIA_LEGACY_EMAIL);
            return user;
        }

        if (!allowRegistration && !UserUtil.isEmpty(storage)) {
            Server server = storage.getObject(Server.class, new Request(new Columns.All()));
            if (!server.getRegistration()) {
                throw new SecurityException("Registration disabled");
            }
        }

        user = new User();
        UserUtil.setUserDefaults(user, config);
        user.setName(name);
        user.setEmail(email);
        user.setFixedEmail(true);
        if (administrator != null) {
            user.setAdministrator(administrator);
        }
        user.setId(storage.addObject(user, new Request(new Columns.Exclude("id"))));
        link(request, user, claims, OpenIdIdentity.VIA_NEW_ACCOUNT);
        return user;
    }

    private void link(HttpServletRequest request, User user, Claims claims, String via)
            throws StorageException, GeneralSecurityException {
        OpenIdIdentity identity = new OpenIdIdentity();
        identity.setUserId(user.getId());
        identity.setIssuer(claims.issuer());
        identity.setSubject(claims.subject());
        identity.setEmail(claims.email());
        identity.setLinkedVia(via);
        identity.setCreatedAt(new Date());
        identity.setLastLoginAt(new Date());
        try {
            identity.setId(storage.addObject(identity, new Request(new Columns.Exclude("id"))));
        } catch (StorageException e) {
            // A concurrent sign-in of the same identity may have linked it first: that is fine for the same
            // account and a conflict for any other.
            OpenIdIdentity existing = find(claims.issuer(), claims.subject());
            if (existing != null && existing.getUserId() == user.getId()) {
                return;
            }
            actionLogger.openIdConflict(request, user.getId());
            throw new GeneralSecurityException("This OpenID identity or account is already linked", e);
        }
        actionLogger.openIdLink(request, user.getId(), identity.getId(), via);
        LOGGER.info("Linked OpenID identity to user {} ({})", user.getId(), via);
    }

    private void reactivateAndRefresh(User user, String name, Boolean administrator) throws StorageException {
        if (OpenIdLifecycle.reactivate(user)) {
            // The provider has just let this user in again after switching the account off itself.
            storage.updateObject(user, new Request(
                    new Columns.Include("disabled", "attributes"),
                    new Condition.Equals("id", user.getId())));
        }
        boolean nameChanged = name != null && !name.equals(user.getName());
        if (nameChanged || administrator != null && user.getAdministrator() != administrator) {
            if (nameChanged) {
                user.setName(name);
            }
            if (administrator != null) {
                user.setAdministrator(administrator);
            }
            storage.updateObject(user, new Request(
                    new Columns.Include("name", "administrator"),
                    new Condition.Equals("id", user.getId())));
        }
    }

    /**
     * Copies a changed email of the provider into the account, unless somebody else's account already has it.
     */
    private void refreshProfileEmail(User user, Claims claims) throws StorageException {
        if (claims.email() == null || claims.email().isBlank() || !claims.emailVerified()) {
            return;
        }
        String email = claims.email().trim().toLowerCase(Locale.ROOT);
        if (user.getEmail() != null && email.equals(user.getEmail().toLowerCase(Locale.ROOT))) {
            return;
        }
        User holder = findUserByEmail(email);
        if (holder != null && holder.getId() != user.getId()) {
            LOGGER.warn("Email of OpenID identity of user {} changed to an address another account has", user.getId());
            return;
        }
        user.setEmail(email);
        storage.updateObject(user, new Request(
                new Columns.Include("email"), new Condition.Equals("id", user.getId())));
    }

}
