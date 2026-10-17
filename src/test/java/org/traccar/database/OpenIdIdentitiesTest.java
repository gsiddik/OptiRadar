package org.traccar.database;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.helper.LogAction;
import org.traccar.model.BaseModel;
import org.traccar.model.OpenIdIdentity;
import org.traccar.model.Permission;
import org.traccar.model.Server;
import org.traccar.model.User;
import org.traccar.storage.MemoryStorage;
import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import jakarta.servlet.http.HttpServletRequest;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class OpenIdIdentitiesTest {

    private static final String ISSUER = "https://nexus.example.test";

    private MemoryStorage storage;
    private LogAction actionLogger;
    private HttpServletRequest request;

    @BeforeEach
    public void setUp() {
        storage = new MemoryStorage();
        actionLogger = mock(LogAction.class);
        request = mock(HttpServletRequest.class);
    }

    private OpenIdIdentities identities(Config config, Storage storage) {
        // The in-memory storage cannot evaluate LOWER(email); the production lookup is the one sign-in uses.
        return new OpenIdIdentities(config, storage, actionLogger) {
            @Override
            protected User findUserByEmail(String lowerCaseEmail) throws StorageException {
                return storage.getObjects(User.class, new Request(new Columns.All())).stream()
                        .filter(user -> user.getEmail() != null
                                && lowerCaseEmail.equals(user.getEmail().toLowerCase(Locale.ROOT)))
                        .findFirst().orElse(null);
            }
        };
    }

    private OpenIdIdentities identities() {
        return identities(new Config(), storage);
    }

    private static OpenIdIdentities.Claims claims(String subject, String email, boolean verified) {
        return new OpenIdIdentities.Claims(ISSUER, subject, email, verified);
    }

    private User addUser(String email) throws Exception {
        User user = new User();
        user.setName("Existing");
        user.setEmail(email);
        user.setId(storage.addObject(user, new Request(new Columns.Exclude("id"))));
        return user;
    }

    private List<OpenIdIdentity> links() {
        return storage.getObjects(OpenIdIdentity.class, new Request(new Columns.All()));
    }

    private User reload(long id) {
        return storage.getObjects(User.class, new Request(new Columns.All())).stream()
                .filter(user -> user.getId() == id).findFirst().orElseThrow();
    }

    @Test
    public void aNewIdentityCreatesALinkedAccount() throws Exception {
        User user = identities().resolve(request, claims("sub-1", "Driver@Example.test", true), "Driver", false);

        assertEquals("driver@example.test", user.getEmail());
        assertEquals(1, links().size());
        OpenIdIdentity link = links().get(0);
        assertEquals(user.getId(), link.getUserId());
        assertEquals(ISSUER, link.getIssuer());
        assertEquals("sub-1", link.getSubject());
        assertEquals(OpenIdIdentity.VIA_NEW_ACCOUNT, link.getLinkedVia());
        verify(actionLogger).openIdLink(request, user.getId(), link.getId(), OpenIdIdentity.VIA_NEW_ACCOUNT);
    }

    @Test
    public void aKnownIdentityKeepsItsAccountWhenTheEmailChanges() throws Exception {
        OpenIdIdentities identities = identities();
        User first = identities.resolve(request, claims("sub-1", "old@example.test", true), "Driver", false);

        User again = identities.resolve(request, claims("sub-1", "new@example.test", true), "Driver", false);

        assertEquals(first.getId(), again.getId());
        assertEquals("new@example.test", reload(first.getId()).getEmail(), "the email is a profile attribute");
        assertEquals(1, links().size());
        assertEquals("new@example.test", links().get(0).getEmail());
        assertNotNull(links().get(0).getLastLoginAt());
    }

    @Test
    public void aChangedEmailThatAnotherAccountHoldsIsNotCopied() throws Exception {
        OpenIdIdentities identities = identities();
        User first = identities.resolve(request, claims("sub-1", "one@example.test", true), "One", false);
        addUser("taken@example.test");

        User again = identities.resolve(request, claims("sub-1", "taken@example.test", true), "One", false);

        assertEquals(first.getId(), again.getId());
        assertEquals("one@example.test", reload(first.getId()).getEmail());
    }

    @Test
    public void anEmailThatChangedHandsDoesNotGiveTheNewPersonTheOldAccount() throws Exception {
        OpenIdIdentities identities = identities();
        User previous = identities.resolve(request, claims("sub-old", "shared@example.test", true), "Previous", false);

        // Somebody else (another subject) is now the owner of the address at the provider.
        assertThrows(GeneralSecurityException.class,
                () -> identities.resolve(request, claims("sub-new", "shared@example.test", true), "New", false));

        assertEquals(1, links().size());
        assertEquals(previous.getId(), links().get(0).getUserId());
        verify(actionLogger).openIdConflict(request, previous.getId());
    }

    @Test
    public void anExistingAccountIsLinkedOnceThroughAVerifiedEmail() throws Exception {
        User legacy = addUser("legacy@example.test");
        OpenIdIdentities identities = identities();

        User user = identities.resolve(request, claims("sub-1", "Legacy@Example.test", true), "Legacy", null);

        assertEquals(legacy.getId(), user.getId());
        assertEquals(1, links().size());
        assertEquals(OpenIdIdentity.VIA_LEGACY_EMAIL, links().get(0).getLinkedVia());
        verify(actionLogger).openIdLink(request, legacy.getId(), links().get(0).getId(), OpenIdIdentity.VIA_LEGACY_EMAIL);

        // Afterwards the identity, not the address, finds the account.
        assertEquals(legacy.getId(), identities.resolve(request, claims("sub-1", "other@example.test", true), "L", null).getId());
        assertEquals(1, links().size());
    }

    @Test
    public void anUnverifiedEmailNeverLinksNorCreatesAnAccount() throws Exception {
        addUser("legacy@example.test");
        OpenIdIdentities identities = identities();

        assertThrows(GeneralSecurityException.class,
                () -> identities.resolve(request, claims("sub-1", "legacy@example.test", false), "X", null));
        assertThrows(GeneralSecurityException.class,
                () -> identities.resolve(request, claims("sub-2", "fresh@example.test", false), "X", null));
        assertThrows(GeneralSecurityException.class,
                () -> identities.resolve(request, claims("sub-3", null, true), "X", null));

        assertTrue(links().isEmpty());
        assertEquals(1, storage.getObjects(User.class, new Request(new Columns.All())).size());
    }

    @Test
    public void anAccountLinkedToAnotherIdentityOfTheSameProviderIsNeverRebound() throws Exception {
        User legacy = addUser("legacy@example.test");
        OpenIdIdentities identities = identities();
        identities.resolve(request, claims("sub-1", "legacy@example.test", true), "Legacy", null);

        assertThrows(GeneralSecurityException.class,
                () -> identities.resolve(request, claims("sub-2", "legacy@example.test", true), "Impostor", null));

        assertEquals(1, links().size());
        assertEquals("sub-1", links().get(0).getSubject());
        assertEquals(legacy.getId(), links().get(0).getUserId());
    }

    @Test
    public void theSameAccountCanHaveAnIdentityPerProvider() throws Exception {
        User legacy = addUser("legacy@example.test");
        OpenIdIdentities identities = identities();
        identities.resolve(request, claims("sub-1", "legacy@example.test", true), "Legacy", null);

        User other = identities.resolve(request,
                new OpenIdIdentities.Claims("https://other.example.test", "sub-9", "legacy@example.test", true),
                "Legacy", null);

        assertEquals(legacy.getId(), other.getId());
        assertEquals(2, links().size());
    }

    @Test
    public void linkingByEmailCanBeSwitchedOff() throws Exception {
        addUser("legacy@example.test");
        Config config = new Config();
        config.setString(Keys.OPENID_LEGACY_EMAIL_LINKING, "false");

        assertThrows(GeneralSecurityException.class, () -> identities(config, storage)
                .resolve(request, claims("sub-1", "legacy@example.test", true), "Legacy", null));
        assertTrue(links().isEmpty());

        // New people can still register, and linked people still sign in.
        assertNotNull(identities(config, storage).resolve(request, claims("sub-2", "fresh@example.test", true), "F", null));
    }

    @Test
    public void registrationRulesStillApplyToNewAccounts() throws Exception {
        addUser("first@example.test");
        Server server = storage.getObject(Server.class, new Request(new Columns.All()));
        server.setRegistration(false);
        storage.updateObject(server, new Request(new Columns.Include("registration"), new Condition.Equals("id", 1L)));

        assertThrows(SecurityException.class,
                () -> identities().resolve(request, claims("sub-1", "new@example.test", true), "New", null));
        assertTrue(links().isEmpty());

        Config config = new Config();
        config.setString(Keys.OPENID_ALLOW_REGISTRATION, "true");
        assertNotNull(identities(config, storage).resolve(request, claims("sub-1", "new@example.test", true), "New", null));
    }

    @Test
    public void onlyAnAccountThatTheProviderSwitchedOffIsSwitchedOnAgain() throws Exception {
        OpenIdIdentities identities = identities();
        User user = identities.resolve(request, claims("sub-1", "driver@example.test", true), "Driver", false);

        user.setDisabled(true);
        user.set(OpenIdLifecycle.DEACTIVATED, true);
        storage.updateObject(user, new Request(new Columns.Include("disabled", "attributes"),
                new Condition.Equals("id", user.getId())));
        assertFalse(identities.resolve(request, claims("sub-1", "driver@example.test", true), "Driver", false).getDisabled());

        User manual = reload(user.getId());
        manual.setDisabled(true);
        manual.removeAttribute(OpenIdLifecycle.DEACTIVATED);
        storage.updateObject(manual, new Request(new Columns.Include("disabled", "attributes"),
                new Condition.Equals("id", user.getId())));
        assertTrue(identities.resolve(request, claims("sub-1", "driver@example.test", true), "Driver", false).getDisabled(),
                "an administrator's own disabling stays");
    }

    /**
     * Storage whose first insert of a link loses a race: a competing sign-in has already stored {@code competing}
     * and the database refuses the second row, as its unique constraint would.
     */
    private static final class RacingStorage extends Storage {
        private final MemoryStorage delegate = new MemoryStorage();
        private OpenIdIdentity competing;

        @Override
        public <T> List<T> getObjects(Class<T> clazz, Request request) throws StorageException {
            return delegate.getObjects(clazz, request);
        }

        @Override
        public <T> Stream<T> getObjectsStream(Class<T> clazz, Request request)
                throws StorageException {
            return delegate.getObjectsStream(clazz, request);
        }

        @Override
        public <T> long addObject(T entity, Request request) throws StorageException {
            if (entity instanceof OpenIdIdentity && competing != null) {
                OpenIdIdentity winner = competing;
                competing = null;
                delegate.addObject(winner, request);
                throw new StorageException("duplicate key value violates unique constraint");
            }
            return delegate.addObject(entity, request);
        }

        @Override
        public <T> void updateObject(T entity, Request request) throws StorageException {
            delegate.updateObject(entity, request);
        }

        @Override
        public void removeObject(Class<?> clazz, Request request) throws StorageException {
            delegate.removeObject(clazz, request);
        }

        @Override
        public List<Permission> getPermissions(
                Class<? extends BaseModel> ownerClass, long ownerId,
                Class<? extends BaseModel> propertyClass, long propertyId) throws StorageException {
            return delegate.getPermissions(ownerClass, ownerId, propertyClass, propertyId);
        }

        @Override
        public void addPermission(Permission permission) throws StorageException {
            delegate.addPermission(permission);
        }

        @Override
        public void removePermission(Permission permission) throws StorageException {
            delegate.removePermission(permission);
        }
    }

    private static OpenIdIdentity identityOf(long userId, String subject) {
        OpenIdIdentity identity = new OpenIdIdentity();
        identity.setUserId(userId);
        identity.setIssuer(ISSUER);
        identity.setSubject(subject);
        identity.setLinkedVia(OpenIdIdentity.VIA_LEGACY_EMAIL);
        return identity;
    }

    @Test
    public void twoSignInsAtTheSameTimeOfTheSameIdentityEndWithOneLinkAndOneAccount() throws Exception {
        RacingStorage racing = new RacingStorage();
        User legacy = new User();
        legacy.setEmail("legacy@example.test");
        legacy.setId(racing.addObject(legacy, new Request(new Columns.Exclude("id"))));
        racing.competing = identityOf(legacy.getId(), "sub-1");

        User user = identities(new Config(), racing)
                .resolve(request, claims("sub-1", "legacy@example.test", true), "Legacy", null);

        assertEquals(legacy.getId(), user.getId());
        assertEquals(1, racing.getObjects(OpenIdIdentity.class, new Request(new Columns.All())).size());
    }

    @Test
    public void aRacingLinkOfAnotherAccountIsAConflictNotASilentSuccess() throws Exception {
        RacingStorage racing = new RacingStorage();
        User legacy = new User();
        legacy.setEmail("legacy@example.test");
        legacy.setId(racing.addObject(legacy, new Request(new Columns.Exclude("id"))));
        racing.competing = identityOf(legacy.getId() + 100, "sub-1");

        assertThrows(GeneralSecurityException.class, () -> identities(new Config(), racing)
                .resolve(request, claims("sub-1", "legacy@example.test", true), "Legacy", null));
        assertEquals(1, racing.getObjects(OpenIdIdentity.class, new Request(new Columns.All())).size());
    }

}
