package org.traccar.database;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.traccar.api.security.LoginService;
import org.traccar.api.security.PermissionsService;
import org.traccar.api.signature.TokenManager;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.helper.LogAction;
import org.traccar.helper.SessionHelper;
import org.traccar.model.Device;
import org.traccar.model.Group;
import org.traccar.model.OpenIdIdentity;
import org.traccar.model.Permission;
import org.traccar.model.User;
import org.traccar.session.cache.CacheManager;
import org.traccar.storage.MemoryStorage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The whole sign-in against a provider that is played by this test: it signs real ID tokens with a real RSA key,
 * checks the PKCE verifier the way a provider does, and hands out one-time authorization codes.
 */
public class OpenIdProviderTest {

    private static final String ISSUER = "https://nexus.example.test";
    private static final String CLIENT = "radar-client";
    private static final String WEB = "https://radar.example.test";
    private static final String TENANT_A = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";
    private static final String TENANT_B = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c02";

    /** One browser: its session cookie and what the server keeps in that session. */
    private static final class Browser {
        private final Map<String, Object> attributes = new ConcurrentHashMap<>();
        private volatile long created = System.currentTimeMillis();
        private final HttpSession session = mock(HttpSession.class);

        Browser() {
            when(session.getAttribute(anyString())).thenAnswer(call -> attributes.get(call.<String>getArgument(0)));
            doAnswer(call -> {
                attributes.put(call.getArgument(0), call.getArgument(1));
                return null;
            }).when(session).setAttribute(anyString(), any());
            doAnswer(call -> {
                attributes.clear();
                created = System.currentTimeMillis();
                return null;
            }).when(session).invalidate();
            when(session.getCreationTime()).thenAnswer(call -> created);
        }

        Map<String, Object> attributes() {
            return attributes;
        }

        HttpSession session() {
            return session;
        }

        HttpServletRequest request(String... parameters) {
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getSession()).thenReturn(session);
            when(request.getSession(true)).thenReturn(session);
            when(request.getSession(false)).thenReturn(session);
            for (int i = 0; i < parameters.length; i += 2) {
                when(request.getParameter(parameters[i])).thenReturn(parameters[i + 1]);
            }
            return request;
        }

        Long userId() {
            return (Long) attributes.get(SessionHelper.USER_ID_KEY);
        }
    }

    /** What the provider knows about a person. */
    private record Person(String subject, String email, boolean verified, String name, String tenant) {
    }

    /** An authorization code the provider handed out. */
    private record Grant(Person person, String nonce, String challenge, String redirect) {
    }

    private final Map<String, Grant> grants = new ConcurrentHashMap<>();
    private final AtomicInteger codes = new AtomicInteger();
    private final List<String> tokenRequests = new ArrayList<>();

    private RSAKey key;
    private MemoryStorage storage;
    private CacheManager cacheManager;
    private OpenIdLifecycle lifecycle;
    private OpenIdIdentities identities;
    private OpenIdProvider provider;
    private Config config;

    @BeforeEach
    public void setUp() throws Exception {
        key = new RSAKeyGenerator(2048).keyID("key-1").generate();
        storage = new MemoryStorage();
        cacheManager = mock(CacheManager.class);
        config = new Config();
        config.setString(Keys.WEB_URL, WEB);
        config.setString(Keys.OPENID_CLIENT_ID, CLIENT);
        config.setString(Keys.OPENID_CLIENT_SECRET, "secret");
        config.setString(Keys.OPENID_ALLOW_REGISTRATION, "true");
        provider = newProvider(config);
    }

    private OpenIdProvider newProvider(Config config) {
        LogAction actionLogger = mock(LogAction.class);
        identities = new OpenIdIdentities(config, storage, actionLogger) {
            @Override
            protected User findUserByEmail(String lowerCaseEmail) throws StorageException {
                return storage.getObjects(User.class, new Request(new Columns.All())).stream()
                        .filter(user -> user.getEmail() != null
                                && lowerCaseEmail.equals(user.getEmail().toLowerCase(Locale.ROOT)))
                        .findFirst().orElse(null);
            }
        };
        lifecycle = new OpenIdLifecycle(config, storage, cacheManager, identities);
        OpenIdTenantLinker linker = new OpenIdTenantLinker(config, storage, cacheManager, actionLogger);
        LoginService loginService = new LoginService(
                config, storage, mock(TokenManager.class), null, () -> mock(PermissionsService.class), identities);
        OpenIdIdTokens idTokens = new OpenIdIdTokens(new Issuer(ISSUER), new ClientID(CLIENT),
                java.util.Set.of(JWSAlgorithm.RS256), new ImmutableJWKSet<>(new JWKSet(key.toPublicJWK())));
        OpenIdProvider.Metadata metadata = new OpenIdProvider.Metadata(
                new Issuer(ISSUER), URI.create(ISSUER + "/oauth/authorize"), URI.create(ISSUER + "/oauth/token"),
                URI.create(ISSUER + "/oauth/userinfo"), null, idTokens, null);
        return new OpenIdProvider(config, loginService, actionLogger, linker, lifecycle, metadata,
                new OpenIdPendingLogins()) {
            @Override
            protected OIDCTokenResponse getToken(URI redirectUri, AuthorizationCode code, CodeVerifier verifier)
                    throws GeneralSecurityException {
                Grant grant = grants.remove(code.getValue());
                if (grant == null) {
                    throw new GeneralSecurityException("invalid_grant");
                }
                tokenRequests.add(verifier.getValue());
                if (!redirectUri.toString().equals(grant.redirect())) {
                    throw new GeneralSecurityException("redirect_uri mismatch");
                }
                if (!CodeChallenge.compute(CodeChallengeMethod.S256, verifier).getValue().equals(grant.challenge())) {
                    throw new GeneralSecurityException("PKCE verification failed");
                }
                try {
                    return new OIDCTokenResponse(new OIDCTokens(
                            SignedJWT.parse(idToken(grant.person().subject(), grant.nonce(), ISSUER)),
                            new BearerAccessToken(grant.person().subject()), null));
                } catch (Exception e) {
                    throw new GeneralSecurityException(e);
                }
            }

            @Override
            protected UserInfo getUserInfo(BearerAccessToken token) {
                Person person = people.get(token.getValue());
                UserInfo info = new UserInfo(new Subject(person.subject()));
                info.setEmailAddress(person.email());
                info.setEmailVerified(person.verified());
                info.setName(person.name());
                if (person.tenant() != null) {
                    info.setClaim("tenant_id", person.tenant());
                }
                if (userInfoSubjectOverride != null) {
                    info = new UserInfo(new Subject(userInfoSubjectOverride));
                    info.setEmailAddress(person.email());
                    info.setEmailVerified(person.verified());
                }
                return info;
            }
        };
    }

    private final Map<String, Person> people = new ConcurrentHashMap<>();
    private String userInfoSubjectOverride;

    private String idToken(String subject, String nonce, String issuer) throws Exception {
        long now = System.currentTimeMillis();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer).subject(subject).audience(CLIENT)
                .issueTime(new Date(now)).expirationTime(new Date(now + 300_000))
                .claim("nonce", nonce).build();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("key-1").type(JOSEObjectType.JWT).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    /** The user is sent to the provider and signs in there: returns the callback query the provider redirects to. */
    private String authenticate(Browser browser, Person person) throws Exception {
        people.put(person.subject(), person);
        URI authUri = provider.createAuthUri(browser.request(), null);
        AuthenticationRequest request = AuthenticationRequest.parse(authUri);
        String code = "code-" + codes.incrementAndGet();
        grants.put(code, new Grant(person, request.getNonce().getValue(),
                request.getCodeChallenge().getValue(), request.getRedirectionURI().toString()));
        return "code=" + code + "&state=" + request.getState().getValue();
    }

    private User signIn(Browser browser, Person person) throws Exception {
        provider.handleCallback(authenticate(browser, person), browser.request());
        return storage.getObjects(User.class, new Request(new Columns.All())).stream()
                .filter(user -> user.getId() == browser.userId()).findFirst().orElseThrow();
    }

    private static Person person(String subject, String email) {
        return new Person(subject, email, true, "Person " + subject, null);
    }

    private int accounts() {
        return storage.getObjects(User.class, new Request(new Columns.All())).size();
    }

    @Test
    public void theAuthorizationRequestCarriesAOneTimeStateANonceAndAnS256Challenge() throws Exception {
        Browser browser = new Browser();

        AuthenticationRequest first = AuthenticationRequest.parse(provider.createAuthUri(browser.request(), null));
        AuthenticationRequest second = AuthenticationRequest.parse(provider.createAuthUri(browser.request(), null));

        assertEquals(CLIENT, first.getClientID().getValue());
        assertEquals(WEB + "/api/session/openid/callback", first.getRedirectionURI().toString());
        assertEquals(CodeChallengeMethod.S256, first.getCodeChallengeMethod());
        assertNotEquals(first.getState(), second.getState());
        assertNotEquals(first.getNonce(), second.getNonce());
        assertNotEquals(first.getCodeChallenge(), second.getCodeChallenge());
    }

    @Test
    public void aCompleteSignInCreatesALinkedAccountAndLogsTheBrowserIn() throws Exception {
        Browser browser = new Browser();

        User user = signIn(browser, person("sub-1", "driver@example.test"));

        assertEquals("driver@example.test", user.getEmail());
        assertEquals(1, storage.getObjects(OpenIdIdentity.class, new Request(new Columns.All())).size());
        assertEquals(1, tokenRequests.size(), "the code was exchanged with the PKCE verifier of this sign-in");
        assertNull(browser.attributes().get(OpenIdProvider.BROWSER_KEY), "the pre-login session is gone");
    }

    @Test
    public void aReplayedCallbackIsRefusedAndSignsNobodyIn() throws Exception {
        Browser browser = new Browser();
        String callback = authenticate(browser, person("sub-1", "driver@example.test"));
        provider.handleCallback(callback, browser.request());
        Browser replayer = new Browser();
        replayer.attributes().putAll(Map.of(OpenIdProvider.BROWSER_KEY, "whatever"));

        assertThrows(GeneralSecurityException.class, () -> provider.handleCallback(callback, browser.request()));
        assertThrows(GeneralSecurityException.class, () -> provider.handleCallback(callback, replayer.request()));
        assertNull(replayer.userId());
    }

    @Test
    public void aCallbackWithoutAnUnknownOrForeignStateIsRefused() throws Exception {
        Browser victim = new Browser();
        Browser attacker = new Browser();
        String attackerCallback = authenticate(attacker, person("sub-attacker", "attacker@example.test"));

        // Login CSRF: the victim's browser is made to complete the attacker's sign-in.
        assertThrows(GeneralSecurityException.class, () -> provider.handleCallback(attackerCallback, victim.request()));
        assertNull(victim.userId());
        assertEquals(0, accounts(), "no account was created either");

        assertThrows(GeneralSecurityException.class,
                () -> provider.handleCallback("code=x&state=never-issued", attacker.request()));
        assertThrows(GeneralSecurityException.class, () -> provider.handleCallback("code=x", attacker.request()));
    }

    @Test
    public void aCallbackAfterTheTimeToLiveIsRefused() throws Exception {
        long[] now = {1_000_000};
        Clock clock = new Clock() {
            @Override
            public ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                return Instant.ofEpochMilli(now[0]);
            }
        };
        OpenIdPendingLogins logins = new OpenIdPendingLogins(clock, 60_000, 10);
        OpenIdPendingLogins.Pending pending = logins.start("b", WEB, "v");
        now[0] += 61_000;
        assertThrows(GeneralSecurityException.class, () -> logins.consume(pending.state(), "b"));
    }

    @Test
    public void anIdTokenMadeForAnotherSignInIsRefused() throws Exception {
        Browser browser = new Browser();
        Person person = person("sub-1", "driver@example.test");
        people.put(person.subject(), person);
        AuthenticationRequest request = AuthenticationRequest.parse(provider.createAuthUri(browser.request(), null));
        // The provider (or a man in the middle) answers with a token minted for a different nonce.
        grants.put("code-x", new Grant(person, "some-other-nonce", request.getCodeChallenge().getValue(),
                request.getRedirectionURI().toString()));

        assertThrows(GeneralSecurityException.class, () -> provider.handleCallback(
                "code=code-x&state=" + request.getState().getValue(), browser.request()));
        assertNull(browser.userId());
        assertEquals(0, accounts());
    }

    @Test
    public void aWrongPkceVerifierAtTheProviderStopsTheExchange() throws Exception {
        Browser browser = new Browser();
        Person person = person("sub-1", "driver@example.test");
        people.put(person.subject(), person);
        AuthenticationRequest request = AuthenticationRequest.parse(provider.createAuthUri(browser.request(), null));
        grants.put("code-x", new Grant(person, request.getNonce().getValue(), "challenge-of-another-sign-in",
                request.getRedirectionURI().toString()));

        assertThrows(GeneralSecurityException.class, () -> provider.handleCallback(
                "code=code-x&state=" + request.getState().getValue(), browser.request()));
        assertNull(browser.userId());
    }

    @Test
    public void aCodeThatWasAlreadyExchangedIsRefused() throws Exception {
        Browser browser = new Browser();
        String callback = authenticate(browser, person("sub-1", "driver@example.test"));
        String code = callback.substring(callback.indexOf('=') + 1, callback.indexOf('&'));
        provider.handleCallback(callback, browser.request());

        Browser second = new Browser();
        AuthenticationRequest request = AuthenticationRequest.parse(provider.createAuthUri(second.request(), null));
        assertThrows(GeneralSecurityException.class, () -> provider.handleCallback(
                "code=" + code + "&state=" + request.getState().getValue(), second.request()));
    }

    @Test
    public void userInfoOfAnotherSubjectThanTheIdTokenIsRefused() throws Exception {
        Browser browser = new Browser();
        userInfoSubjectOverride = "sub-of-somebody-else";

        assertThrows(GeneralSecurityException.class,
                () -> provider.handleCallback(authenticate(browser, person("sub-1", "driver@example.test")),
                        browser.request()));
        assertNull(browser.userId());
        assertEquals(0, accounts());
    }

    @Test
    public void anIssuerMismatchInTheCallbackIsRefused() throws Exception {
        Browser browser = new Browser();
        String callback = authenticate(browser, person("sub-1", "driver@example.test"));

        assertThrows(GeneralSecurityException.class, () -> provider.handleCallback(
                callback + "&iss=https%3A%2F%2Fevil.example.test", browser.request()));
        assertNull(browser.userId());

        Browser other = new Browser();
        String good = authenticate(other, person("sub-1", "driver@example.test"));
        provider.handleCallback(good + "&iss=" + java.net.URLEncoder.encode(ISSUER, java.nio.charset.StandardCharsets.UTF_8),
                other.request());
        assertTrue(other.userId() != null);
    }

    @Test
    public void theMobileRedirectIsOffByDefaultAndNeverAcceptedOnTheCallback() throws Exception {
        Browser browser = new Browser();

        assertThrows(GeneralSecurityException.class,
                () -> provider.createAuthUri(browser.request(), "org.traccar.manager://openid"));

        String callback = authenticate(browser, person("sub-1", "driver@example.test"));
        HttpServletRequest sneaky = browser.request("redirect_uri", "org.traccar.manager://openid");
        assertThrows(GeneralSecurityException.class, () -> provider.handleCallback(callback, sneaky));
    }

    @Test
    public void theMobileRedirectWorksWhenSwitchedOnButOnlyForTheCustomScheme() throws Exception {
        Config mobile = new Config();
        mobile.setString(Keys.WEB_URL, WEB);
        mobile.setString(Keys.OPENID_CLIENT_ID, CLIENT);
        mobile.setString(Keys.OPENID_CLIENT_SECRET, "secret");
        mobile.setString(Keys.OPENID_ALLOW_REGISTRATION, "true");
        mobile.setString(Keys.OPENID_ALLOW_MOBILE_REDIRECT, "true");
        OpenIdProvider mobileProvider = newProvider(mobile);
        Browser app = new Browser();

        assertThrows(GeneralSecurityException.class,
                () -> mobileProvider.createAuthUri(app.request(), "https://evil.example.test/steal"));
        URI uri = mobileProvider.createAuthUri(app.request(), "org.traccar.manager://openid");
        AuthenticationRequest request = AuthenticationRequest.parse(uri);
        assertEquals("org.traccar.manager://openid", request.getRedirectionURI().toString());

        Person person = person("sub-1", "driver@example.test");
        people.put(person.subject(), person);
        grants.put("code-m", new Grant(person, request.getNonce().getValue(), request.getCodeChallenge().getValue(),
                "org.traccar.manager://openid"));
        mobileProvider.handleCallback("code=code-m&state=" + request.getState().getValue(),
                new Browser().request("redirect_uri", "org.traccar.manager://openid"));
        assertEquals(1, accounts());
    }

    @Test
    public void aRepeatedSignInOfTheSameIdentityKeepsTheAccountEvenIfTheEmailChanged() throws Exception {
        User first = signIn(new Browser(), person("sub-1", "old@example.test"));

        User again = signIn(new Browser(), person("sub-1", "new@example.test"));

        assertEquals(first.getId(), again.getId());
        assertEquals(1, accounts());
        assertEquals("new@example.test", again.getEmail());
    }

    @Test
    public void anAdministratorDisabledAccountCannotSignIn() throws Exception {
        User user = signIn(new Browser(), person("sub-1", "driver@example.test"));
        user.setDisabled(true);
        storage.updateObject(user, new Request(new Columns.Include("disabled"), new Condition.Equals("id", user.getId())));

        Browser browser = new Browser();
        assertThrows(SecurityException.class, () -> signIn(browser, person("sub-1", "driver@example.test")));
        assertNull(browser.userId());
    }

    @Test
    public void aUserWhoLostAccessAtTheProviderCanSignInAgainOnlyAfterTheProviderLetsThemIn() throws Exception {
        User user = signIn(new Browser(), person("sub-1", "driver@example.test"));
        lifecycle.apply(new OpenIdLogoutTokens.Event(ISSUER, "sub-1", "driver@example.test", true, false, null));

        // Signing in means the provider has let the user in again: the account it switched off is switched on.
        User back = signIn(new Browser(), person("sub-1", "driver@example.test"));

        assertEquals(user.getId(), back.getId());
        assertFalse(back.getDisabled());
    }

    private Config tenantConfig() {
        Config tenants = new Config();
        tenants.setString(Keys.WEB_URL, WEB);
        tenants.setString(Keys.OPENID_CLIENT_ID, CLIENT);
        tenants.setString(Keys.OPENID_CLIENT_SECRET, "secret");
        tenants.setString(Keys.OPENID_ALLOW_REGISTRATION, "true");
        tenants.setString(Keys.OPENID_TENANT_CLAIM, "tenant_id");
        return tenants;
    }

    private Group addTenantGroup(String name, String tenant) throws Exception {
        Group group = new Group();
        group.setName(name);
        group.set("optinexusTenantId", tenant);
        group.setId(storage.addObject(group, new Request(new Columns.Exclude("id"))));
        return group;
    }

    @Test
    public void signingInToTenantBEndsTheOpenSessionOfTenantAAndNeverLeaksItsData() throws Exception {
        provider = newProvider(tenantConfig());
        Group a = addTenantGroup("Tenant A", TENANT_A);
        Group b = addTenantGroup("Tenant B", TENANT_B);
        Device truckOfA = new Device();
        truckOfA.setName("truck-a");
        truckOfA.setUniqueId("truck-a");
        truckOfA.setGroupId(a.getId());
        truckOfA.setId(storage.addObject(truckOfA, new Request(new Columns.Exclude("id"))));

        Browser browserA = new Browser();
        User user = signIn(browserA, new Person("sub-1", "driver@example.test", true, "Driver", TENANT_A));
        storage.addPermission(new Permission(User.class, user.getId(), Device.class, truckOfA.getId()));
        assertFalse(OpenIdLifecycle.isSessionRevoked(reload(user), browserA.session()), "tenant A session is valid");
        Thread.sleep(5);

        Browser browserB = new Browser();
        signIn(browserB, new Person("sub-1", "driver@example.test", true, "Driver", TENANT_B));

        User stored = reload(user);
        assertTrue(OpenIdLifecycle.isSessionRevoked(stored, browserA.session()),
                "the older session does not silently continue with tenant B's scope");
        assertFalse(OpenIdLifecycle.isSessionRevoked(stored, browserB.session()));
        assertEquals(List.of(b.getId()), storage.getPermissions(User.class, user.getId(), Group.class, 0).stream()
                .map(Permission::getPropertyId).toList());
        assertTrue(storage.getPermissions(User.class, user.getId(), Device.class, 0).isEmpty(),
                "a direct permission on a device of tenant A did not survive the move");
    }

    @Test
    public void signingInToTheSameTenantTwiceKeepsBothSessions() throws Exception {
        provider = newProvider(tenantConfig());
        addTenantGroup("Tenant A", TENANT_A);
        Person person = new Person("sub-1", "driver@example.test", true, "Driver", TENANT_A);

        Browser first = new Browser();
        User user = signIn(first, person);
        Thread.sleep(5);
        signIn(new Browser(), person);

        assertFalse(OpenIdLifecycle.isSessionRevoked(reload(user), first.session()));
    }

    @Test
    public void aTenantThatIsNotSetUpCreatesNoAccountAndAnUnverifiedEmailIsRefused() throws Exception {
        provider = newProvider(tenantConfig());
        addTenantGroup("Tenant A", TENANT_A);

        Browser unknown = new Browser();
        assertThrows(GeneralSecurityException.class,
                () -> signIn(unknown, new Person("sub-1", "a@example.test", true, "A", TENANT_B)));
        Browser unverified = new Browser();
        assertThrows(GeneralSecurityException.class,
                () -> signIn(unverified, new Person("sub-2", "b@example.test", false, "B", TENANT_A)));

        assertEquals(0, accounts());
    }

    private User reload(User user) {
        return storage.getObjects(User.class, new Request(new Columns.All())).stream()
                .filter(item -> item.getId() == user.getId()).findFirst().orElseThrow();
    }

    @Test
    public void concurrentSignInsOfDifferentPeopleNeverMixAccountsOrSessions() throws Exception {
        int people = 12;
        ExecutorService pool = Executors.newFixedThreadPool(people);
        List<Future<Long>> results = new ArrayList<>();
        List<Browser> browsers = new ArrayList<>();
        List<String> callbacks = new ArrayList<>();
        for (int i = 0; i < people; i++) {
            Browser browser = new Browser();
            browsers.add(browser);
            callbacks.add(authenticate(browser, person("sub-" + i, "person" + i + "@example.test")));
        }
        for (int i = 0; i < people; i++) {
            Browser browser = browsers.get(i);
            String callback = callbacks.get(i);
            results.add(pool.submit(() -> {
                provider.handleCallback(callback, browser.request());
                return browser.userId();
            }));
        }
        List<Long> ids = new ArrayList<>();
        for (Future<Long> result : results) {
            ids.add(result.get());
        }
        pool.shutdown();

        assertEquals(people, ids.stream().distinct().count());
        assertEquals(people, accounts());
        for (int i = 0; i < people; i++) {
            long id = ids.get(i);
            assertEquals("person" + i + "@example.test", storage.getObjects(User.class, new Request(new Columns.All()))
                    .stream().filter(user -> user.getId() == id).findFirst().orElseThrow().getEmail());
        }
    }

    @Test
    public void concurrentCallbacksWithTheSameStateLetExactlyOneThrough() throws Exception {
        Browser browser = new Browser();
        String callback = authenticate(browser, person("sub-1", "driver@example.test"));
        int attempts = 16;
        ExecutorService pool = Executors.newFixedThreadPool(attempts);
        List<Future<Boolean>> results = new ArrayList<>();
        for (int i = 0; i < attempts; i++) {
            results.add(pool.submit(() -> {
                try {
                    provider.handleCallback(callback, browser.request());
                    return true;
                } catch (GeneralSecurityException e) {
                    return false;
                }
            }));
        }
        int accepted = 0;
        for (Future<Boolean> result : results) {
            if (result.get()) {
                accepted++;
            }
        }
        pool.shutdown();

        assertEquals(1, accepted);
        assertEquals(1, accounts());
    }

    @Test
    public void discoveryFreeConfigurationNeedsTheIssuerAndTheKeySet() {
        Config manual = new Config();
        manual.setString(Keys.OPENID_CLIENT_ID, CLIENT);
        manual.setString(Keys.OPENID_CLIENT_SECRET, "secret");
        manual.setString(Keys.OPENID_AUTH_URL, ISSUER + "/authorize");
        manual.setString(Keys.OPENID_TOKEN_URL, ISSUER + "/token");
        manual.setString(Keys.OPENID_USERINFO_URL, ISSUER + "/userinfo");

        assertThrows(IllegalStateException.class, () -> new OpenIdProvider(
                manual, null, mock(LogAction.class), null, null));
    }

}
