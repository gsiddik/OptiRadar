package org.traccar.database;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.traccar.config.Config;
import org.traccar.helper.LogAction;
import org.traccar.model.Group;
import org.traccar.model.ObjectOperation;
import org.traccar.model.OpenIdIdentity;
import org.traccar.model.Permission;
import org.traccar.model.User;
import org.traccar.session.cache.CacheManager;
import org.traccar.storage.MemoryStorage;
import org.traccar.storage.Storage;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import jakarta.servlet.http.HttpSession;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class OpenIdLifecycleTest {

    private static final String ISSUER = "https://nexus.example.test";
    private static final String TENANT_A = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";
    private static final String TENANT_B = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c02";

    private Storage storage;
    private CacheManager cacheManager;
    private OpenIdLifecycle lifecycle;

    @BeforeEach
    public void setUp() {
        storage = new MemoryStorage();
        cacheManager = mock(CacheManager.class);
        OpenIdIdentities identities = new OpenIdIdentities(new Config(), storage, mock(LogAction.class));
        lifecycle = new OpenIdLifecycle(new Config(), storage, cacheManager, identities);
    }

    private User addUser(String email) throws Exception {
        User user = new User();
        user.setEmail(email);
        user.setId(storage.addObject(user, new Request(new Columns.Exclude("id"))));
        return user;
    }

    /** An account that signed in through the provider as {@code subject}. */
    private User addLinkedUser(String email, String subject) throws Exception {
        User user = addUser(email);
        OpenIdIdentity identity = new OpenIdIdentity();
        identity.setUserId(user.getId());
        identity.setIssuer(ISSUER);
        identity.setSubject(subject);
        identity.setLinkedVia(OpenIdIdentity.VIA_NEW_ACCOUNT);
        storage.addObject(identity, new Request(new Columns.Exclude("id")));
        return user;
    }

    private Group addGroup(String tenantId) throws Exception {
        Group group = new Group();
        group.setName("Group " + tenantId);
        if (tenantId != null) {
            group.set("optinexusTenantId", tenantId);
        }
        group.setId(storage.addObject(group, new Request(new Columns.Exclude("id"))));
        return group;
    }

    private User reload(User user) throws Exception {
        return storage.getObjects(User.class, new Request(new Columns.All())).stream()
                .filter(item -> item.getId() == user.getId()).findFirst().orElseThrow();
    }

    private static OpenIdLogoutTokens.Event logout(String subject) {
        return new OpenIdLogoutTokens.Event(ISSUER, subject, "whatever@example.test", false, false, null);
    }

    private static OpenIdLogoutTokens.Event revoked(String subject) {
        return new OpenIdLogoutTokens.Event(ISSUER, subject, "whatever@example.test", true, false, null);
    }

    private static HttpSession sessionCreatedAt(long millis) {
        HttpSession session = mock(HttpSession.class);
        when(session.getCreationTime()).thenReturn(millis);
        return session;
    }

    @Test
    public void aLogoutEndsEarlierSessionsButNotLaterOnesAndKeepsTheAccountEnabled() throws Exception {
        User user = addLinkedUser("driver@example.test", "sub-1");
        long before = System.currentTimeMillis() - 5000;

        lifecycle.apply(logout("sub-1"));

        User stored = reload(user);
        assertFalse(stored.getDisabled());
        assertNull(stored.getAttributes().get(OpenIdLifecycle.DEACTIVATED));
        assertTrue(OpenIdLifecycle.isSessionRevoked(stored, sessionCreatedAt(before)));
        assertFalse(OpenIdLifecycle.isSessionRevoked(stored, sessionCreatedAt(System.currentTimeMillis() + 1000)));
        verify(cacheManager).invalidateObject(true, User.class, user.getId(), ObjectOperation.UPDATE);
    }

    @Test
    public void aUserThatWasNeverLoggedOutKeepsAllSessions() throws Exception {
        User user = addLinkedUser("driver@example.test", "sub-1");

        assertFalse(OpenIdLifecycle.isSessionRevoked(reload(user), sessionCreatedAt(1)));
    }

    @Test
    public void revokedAccessDisablesTheAccountAndMarksItSoOnlyTheProviderCanUndoIt() throws Exception {
        User user = addLinkedUser("driver@example.test", "sub-1");

        lifecycle.apply(revoked("sub-1"));

        User stored = reload(user);
        assertTrue(stored.getDisabled());
        assertTrue(stored.getBoolean(OpenIdLifecycle.DEACTIVATED));
        assertTrue(OpenIdLifecycle.reactivate(stored));
        assertFalse(stored.getDisabled());
        assertNull(stored.getAttributes().get(OpenIdLifecycle.DEACTIVATED));
        assertFalse(OpenIdLifecycle.reactivate(stored));
    }

    @Test
    public void anAccountAnAdministratorDisabledIsNeverMarkedOrReactivated() throws Exception {
        User user = addLinkedUser("driver@example.test", "sub-1");
        user.setDisabled(true);
        storage.updateObject(user, new Request(new Columns.Include("disabled"),
                new Condition.Equals("id", user.getId())));

        lifecycle.apply(revoked("sub-1"));

        User stored = reload(user);
        assertTrue(stored.getDisabled());
        assertNull(stored.getAttributes().get(OpenIdLifecycle.DEACTIVATED));
        assertFalse(OpenIdLifecycle.reactivate(stored));
        assertTrue(stored.getDisabled());
    }

    @Test
    public void revokedAccessForOneTenantOnlyLeavesThatTenantsGroup() throws Exception {
        Group a = addGroup(TENANT_A);
        Group b = addGroup(TENANT_B);
        Group shared = addGroup(null);
        User user = addLinkedUser("driver@example.test", "sub-1");
        for (Group group : List.of(a, b, shared)) {
            storage.addPermission(new Permission(User.class, user.getId(), Group.class, group.getId()));
        }

        lifecycle.apply(new OpenIdLogoutTokens.Event(
                ISSUER, "sub-1", "driver@example.test", true, true, TENANT_A.toUpperCase()));

        List<Long> groups = storage.getPermissions(User.class, user.getId(), Group.class, 0).stream()
                .map(Permission::getPropertyId).sorted().toList();
        assertEquals(List.of(b.getId(), shared.getId()).stream().sorted().toList(), groups);
        assertFalse(reload(user).getDisabled());
        assertTrue(reload(user).getLong(OpenIdLifecycle.SESSIONS_NOT_BEFORE) > 0);
        verify(cacheManager).invalidatePermission(true, User.class, user.getId(), Group.class, a.getId(), false);
    }

    @Test
    public void anUnknownSubjectChangesNothing() throws Exception {
        User user = addLinkedUser("driver@example.test", "sub-1");

        lifecycle.apply(revoked("sub-unknown"));
        lifecycle.apply(revoked(null));

        assertFalse(reload(user).getDisabled());
        assertEquals(0L, reload(user).getLong(OpenIdLifecycle.SESSIONS_NOT_BEFORE));
    }

    @Test
    public void theEmailInTheTokenNeverSelectsTheAccount() throws Exception {
        // The address of an old account was reused by another person (another subject): that person's logout or
        // revocation must not touch the account that merely carries the address.
        User oldOwner = addLinkedUser("shared@example.test", "sub-old");
        addUser("somebody@example.test");

        lifecycle.apply(new OpenIdLogoutTokens.Event(ISSUER, "sub-new", "shared@example.test", true, false, null));

        assertFalse(reload(oldOwner).getDisabled());
        assertEquals(0L, reload(oldOwner).getLong(OpenIdLifecycle.SESSIONS_NOT_BEFORE));
    }

    @Test
    public void anAccountIsFoundByItsIdentityEvenWhenItsEmailChanged() throws Exception {
        User user = addLinkedUser("old.address@example.test", "sub-1");

        lifecycle.apply(new OpenIdLogoutTokens.Event(ISSUER, "sub-1", "new.address@example.test", true, false, null));

        assertTrue(reload(user).getDisabled());
    }

    @Test
    public void aSubjectOfAnotherIssuerIsAnotherPerson() throws Exception {
        User user = addLinkedUser("driver@example.test", "sub-1");

        lifecycle.apply(new OpenIdLogoutTokens.Event(
                "https://other-issuer.example.test", "sub-1", "driver@example.test", true, false, null));

        assertFalse(reload(user).getDisabled());
    }

    @Test
    public void endingSessionsOnlyRevokesSessionsThatBeganEarlier() throws Exception {
        User user = addLinkedUser("driver@example.test", "sub-1");
        long before = System.currentTimeMillis() - 5000;

        lifecycle.endSessions(user);

        User stored = reload(user);
        assertTrue(OpenIdLifecycle.isSessionRevoked(stored, sessionCreatedAt(before)));
        assertFalse(OpenIdLifecycle.isSessionRevoked(stored, sessionCreatedAt(System.currentTimeMillis() + 1000)));
        assertFalse(stored.getDisabled());
    }

    @Test
    public void rememberingTheLogoutUrlWritesOnlyWhenItChanged() throws Exception {
        User user = addLinkedUser("driver@example.test", "sub-1");

        lifecycle.rememberLogoutUrl(user, "https://nexus.example.test/oidc/logout?client_id=radar");
        assertEquals("https://nexus.example.test/oidc/logout?client_id=radar",
                reload(user).getAttributes().get(OpenIdLifecycle.LOGOUT_URL));

        lifecycle.rememberLogoutUrl(user, null);
        assertEquals("https://nexus.example.test/oidc/logout?client_id=radar",
                reload(user).getAttributes().get(OpenIdLifecycle.LOGOUT_URL));
    }

}
