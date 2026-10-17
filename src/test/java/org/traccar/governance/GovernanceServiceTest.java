package org.traccar.governance;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.traccar.api.security.ServiceAccountUser;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.database.OpenIdIdentities;
import org.traccar.database.OpenIdLifecycle;
import org.traccar.database.OpenIdTenantLinker;
import org.traccar.helper.LogAction;
import org.traccar.model.Group;
import org.traccar.model.OpenIdIdentity;
import org.traccar.model.Permission;
import org.traccar.model.User;
import org.traccar.session.cache.CacheManager;
import org.traccar.storage.MemoryStorage;
import org.traccar.storage.Storage;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import jakarta.ws.rs.client.ClientBuilder;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

public class GovernanceServiceTest {

    private static final String TENANT_A = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";
    private static final String TENANT_B = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c02";
    private static final String SUBJECT_1 = "5d3a7f9e-1b2c-4d5e-8f60-7a8b9c0d1e01";
    private static final String SUBJECT_2 = "5d3a7f9e-1b2c-4d5e-8f60-7a8b9c0d1e02";
    private static final String ISSUER = "https://nexus.example.test";
    private static final String APP = "optiradar";

    private final AtomicLong clock = new AtomicLong(System.currentTimeMillis());

    private FakeNexus nexus;
    private Storage storage;
    private OpenIdLifecycle lifecycle;
    private Group groupA;
    private Group groupB;

    // What the fake OptiNexus answers; tests change these.
    private volatile String permissionsBody;
    private volatile String commercialBody;
    private volatile FakeNexus.Reply permissionsReply;
    private volatile FakeNexus.Reply commercialReply;

    @BeforeEach
    public void setUp() throws Exception {
        nexus = new FakeNexus();
        storage = new MemoryStorage();
        permissionsBody = grants(SUBJECT_1, TENANT_A, true, null, 300, Catalog.LIVE_VIEW, Catalog.DEVICES_VIEW,
                Catalog.REPORTS_VIEW);
        commercialBody = commercial(TENANT_A, "ACTIVE", List.of(APP, "optifleet"),
                List.of("optiradar.tracking.live", "optiradar.devices.registry", "optiradar.reporting.standard"),
                List.of());
        permissionsReply = null;
        commercialReply = null;
        nexus.route("POST", "/api/v1/authorization/effective-permissions", GovernanceService.SCOPE_AUTHORIZATION,
                call -> permissionsReply != null ? permissionsReply : FakeNexus.Reply.ok(permissionsBody));
        nexus.route("GET", "/api/v1/tenants/", GovernanceService.SCOPE_COMMERCIAL,
                call -> commercialReply != null ? commercialReply : FakeNexus.Reply.ok(commercialBody));

        groupA = addGroup("Tenant A", TENANT_A);
        groupB = addGroup("Tenant B", TENANT_B);
    }

    @AfterEach
    public void tearDown() {
        nexus.close();
    }

    private String grants(String subject, String tenant, boolean allowed, String reason, int ttl, String... keys) {
        return FakeNexus.effectivePermissions(subject, tenant, APP, allowed, reason, ttl, keys);
    }

    private String commercial(
            String tenant, String status, List<String> applications, List<String> on, List<String> off) {
        return FakeNexus.commercialContext(tenant, status, applications, on, off);
    }

    private Group addGroup(String name, String tenantId) throws Exception {
        Group group = new Group();
        group.setName(name);
        if (tenantId != null) {
            group.set("optinexusTenantId", tenantId);
        }
        group.setId(storage.addObject(group, new Request(new Columns.Exclude("id"))));
        return group;
    }

    private Config config() {
        Config config = new Config();
        config.setString(Keys.GOVERNANCE_ENABLE, "true");
        config.setString(Keys.OPENID_TENANT_CLAIM, "tenant_id");
        config.setString(Keys.OPTINEXUS_BASE_URL, nexus.baseUrl());
        config.setString(Keys.OPTINEXUS_CLIENT_ID, "radar-client");
        config.setString(Keys.OPTINEXUS_CLIENT_SECRET, "radar-secret");
        return config;
    }

    private GovernanceService service() {
        return service(config());
    }

    private GovernanceService service(Config config) {
        NexusClient client = new NexusClient(config, ClientBuilder.newClient(), new ObjectMapper()) {
            @Override
            protected long now() {
                return clock.get();
            }
        };
        CacheManager cacheManager = mock(CacheManager.class);
        LogAction logAction = mock(LogAction.class);
        OpenIdIdentities identities = new OpenIdIdentities(config, storage, logAction);
        OpenIdTenantLinker linker = new OpenIdTenantLinker(config, storage, cacheManager, logAction);
        lifecycle = new OpenIdLifecycle(config, storage, cacheManager, identities);
        return new GovernanceService(config, storage, client, identities, linker, lifecycle) {
            @Override
            protected long now() {
                return clock.get();
            }
        };
    }

    private User addUser(String login, boolean administrator, boolean readonly) throws Exception {
        User user = new User();
        user.setLogin(login);
        user.setEmail(login + "@example.test");
        user.setAdministrator(administrator);
        user.setReadonly(readonly);
        user.setId(storage.addObject(user, new Request(new Columns.Exclude("id"))));
        return user;
    }

    private User addTenantUser(String login, String subject, Group... groups) throws Exception {
        User user = addUser(login, false, false);
        OpenIdIdentity identity = new OpenIdIdentity();
        identity.setUserId(user.getId());
        identity.setIssuer(ISSUER);
        identity.setSubject(subject);
        identity.setLastLoginAt(new Date());
        storage.addObject(identity, new Request(new Columns.Exclude("id")));
        for (Group group : groups) {
            storage.addPermission(new Permission(User.class, user.getId(), Group.class, group.getId()));
        }
        return user;
    }

    private GovernanceException refused(Runnable action) {
        return assertThrows(GovernanceException.class, action::run);
    }

    // ---------------------------------------------------------------------------------------------------------
    // Who is acting

    @Test
    public void administratorAndServiceAccountAreOperators() throws Exception {
        GovernanceService service = service();
        User admin = addUser("admin", true, false);
        assertEquals(GovernedPrincipal.Kind.OPERATOR, service.principal(admin.getId()).kind());
        assertEquals(GovernedPrincipal.Kind.OPERATOR, service.principal(ServiceAccountUser.ID).kind());
        assertTrue(nexus.calls().isEmpty(), "deciding who acts never needs OptiNexus");
    }

    @Test
    public void tenantUserIsCentralWithSubjectAndTenant() throws Exception {
        GovernanceService service = service();
        User user = addTenantUser("alice", SUBJECT_1.toUpperCase(), groupA);

        GovernedPrincipal principal = service.principal(user.getId());

        assertEquals(GovernedPrincipal.Kind.CENTRAL, principal.kind());
        assertEquals(SUBJECT_1, principal.subject());
        assertEquals(TENANT_A, principal.tenantId());
    }

    @Test
    public void tenantComesFromTheNearestTenantGroupAboveTheLinkedGroup() throws Exception {
        GovernanceService service = service();
        Group child = new Group();
        child.setName("Depot");
        child.setGroupId(groupA.getId());
        child.setId(storage.addObject(child, new Request(new Columns.Exclude("id"))));
        User user = addTenantUser("alice", SUBJECT_1, child);

        assertEquals(TENANT_A, service.principal(user.getId()).tenantId());
    }

    @Test
    public void passwordUserWithoutIdentityIsDenied() throws Exception {
        GovernanceService service = service();
        User user = addUser("local", false, false);

        GovernedPrincipal principal = service.principal(user.getId());

        assertEquals(GovernedPrincipal.Kind.DENIED, principal.kind());
        assertEquals(GovernanceException.IDENTITY_REQUIRED, principal.code());
        assertEquals(GovernanceException.IDENTITY_REQUIRED,
                refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW))).getCode());
    }

    @Test
    public void unknownAccountIsDenied() {
        assertEquals(GovernedPrincipal.Kind.DENIED, service().principal(9999).kind());
    }

    @Test
    public void accountOfTwoTenantsOrNoTenantIsDeniedNeverMerged() throws Exception {
        GovernanceService service = service();
        User both = addTenantUser("both", SUBJECT_1, groupA, groupB);
        User none = addTenantUser("none", SUBJECT_2);

        assertEquals(GovernanceException.TENANT_UNRESOLVED, service.principal(both.getId()).code());
        assertEquals(GovernanceException.TENANT_UNRESOLVED, service.principal(none.getId()).code());
    }

    @Test
    public void subjectOrTenantThatIsNotAnOptiNexusIdIsDenied() throws Exception {
        GovernanceService service = service();
        User badSubject = addTenantUser("bad", "not-a-uuid", groupA);
        Group odd = addGroup("Odd", "acme");
        User badTenant = addTenantUser("odd", SUBJECT_2, odd);

        assertEquals(GovernanceException.TENANT_UNRESOLVED, service.principal(badSubject.getId()).code());
        assertEquals(GovernanceException.TENANT_UNRESOLVED, service.principal(badTenant.getId()).code());
    }

    @Test
    public void onlyListedReadonlyAccountsAreIntegrationPrincipals() throws Exception {
        Config config = config();
        config.setString(Keys.GOVERNANCE_INTEGRATION_USERS, " Connector@Example.test , other ");
        GovernanceService service = service(config);
        User connector = addUser("connector", false, true);
        User writer = addUser("writer", false, false);
        User unlisted = addUser("unlisted", false, true);
        User admin = addUser("other", true, true);

        assertEquals(GovernedPrincipal.Kind.INTEGRATION, service.principal(connector.getId()).kind());
        assertEquals(GovernedPrincipal.Kind.DENIED, service.principal(unlisted.getId()).kind());
        assertEquals(GovernedPrincipal.Kind.OPERATOR, service.principal(admin.getId()).kind());
        // a listed account that is not read-only is not an integration account
        Config second = config();
        second.setString(Keys.GOVERNANCE_INTEGRATION_USERS, "writer");
        assertEquals(GovernedPrincipal.Kind.DENIED, service(second).principal(writer.getId()).kind());
    }

    @Test
    public void nativeFlagChangesAreSeenWithinTheCacheWindow() throws Exception {
        GovernanceService service = service();
        User user = addTenantUser("alice", SUBJECT_1, groupA);
        assertEquals(GovernedPrincipal.Kind.CENTRAL, service.principal(user).kind());

        user.setAdministrator(true);

        assertEquals(GovernedPrincipal.Kind.OPERATOR, service.principal(user).kind());
    }

    // ---------------------------------------------------------------------------------------------------------
    // Grants and entitlements

    @Test
    public void grantedAndEntitledPermissionPasses() throws Exception {
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        assertDoesNotThrow(() -> service.require(principal, List.of(Catalog.LIVE_VIEW, Catalog.DEVICES_VIEW)));
    }

    @Test
    public void requestsToOptiNexusCarryTheDocumentedBodyAndTheRightScope() throws Exception {
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        service.require(principal, List.of(Catalog.LIVE_VIEW));

        FakeNexus.Call permissions = nexus.calls("/api/v1/authorization/effective-permissions").get(0);
        assertEquals(GovernanceService.SCOPE_AUTHORIZATION, permissions.scope());
        assertEquals(SUBJECT_1, new ObjectMapper().readTree(permissions.body()).path("user_id").asText());
        assertEquals(TENANT_A, new ObjectMapper().readTree(permissions.body()).path("tenant_id").asText());
        assertEquals(APP, new ObjectMapper().readTree(permissions.body()).path("application_code").asText());
        FakeNexus.Call commercial = nexus.calls("/api/v1/tenants/").get(0);
        assertEquals("/api/v1/tenants/" + TENANT_A + "/commercial-context", commercial.path());
        assertEquals(GovernanceService.SCOPE_COMMERCIAL, commercial.scope());
        assertEquals(2, nexus.calls("/api/v1/oauth/token").size(), "one token per scope");
    }

    @Test
    public void permissionNotGrantedIsDeniedWithTheName() throws Exception {
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        GovernanceException e = refused(() -> service.require(principal, List.of(Catalog.COMMANDS_SEND)));

        assertEquals(403, e.getStatus());
        assertEquals(GovernanceException.PERMISSION_DENIED, e.getCode());
        assertEquals(Catalog.COMMANDS_SEND, e.getPermission());
    }

    @Test
    public void everyPermissionOfARequestMustBeGranted() throws Exception {
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        GovernanceException e = refused(() -> service.require(principal,
                List.of(Catalog.LIVE_VIEW, Catalog.DEVICES_MANAGE)));

        assertEquals(Catalog.DEVICES_MANAGE, e.getPermission());
    }

    @Test
    public void grantsOfAnotherApplicationAndUnknownKeysNeverCount() throws Exception {
        permissionsBody = grants(SUBJECT_1, TENANT_A, true, null, 300, "optifleet.fleet.view", "optiradar.made.up",
                Catalog.LIVE_VIEW);
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        assertDoesNotThrow(() -> service.require(principal, List.of(Catalog.LIVE_VIEW)));
        assertEquals(GovernanceException.PERMISSION_DENIED,
                refused(() -> service.require(principal, List.of("optifleet.fleet.view"))).getCode());
        assertEquals(GovernanceException.PERMISSION_DENIED,
                refused(() -> service.require(principal, List.of("optiradar.made.up"))).getCode());
        assertEquals(List.of(Catalog.LIVE_VIEW), service.context(principal).permissions());
    }

    @Test
    public void tenantWithoutTheApplicationIsNotEntitled() throws Exception {
        commercialBody = commercial(TENANT_A, "ACTIVE", List.of("optifleet"), List.of("optiradar.tracking.live"),
                List.of());
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        GovernanceException e = refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW)));

        assertEquals(GovernanceException.NOT_ENTITLED, e.getCode());
        assertEquals(403, e.getStatus());
    }

    @Test
    public void suspendedTenantIsNotEntitled() throws Exception {
        commercialBody = commercial(TENANT_A, "SUSPENDED", List.of(APP), List.of("optiradar.tracking.live"), List.of());
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        assertEquals(GovernanceException.NOT_ENTITLED,
                refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW))).getCode());
    }

    @Test
    public void featureNotBoughtIsNotEntitledEvenWhenTheUserHoldsThePermission() throws Exception {
        // reporting.reports is missing from the enabled capabilities
        commercialBody = commercial(TENANT_A, "ACTIVE", List.of(APP),
                List.of("optiradar.tracking.live", "optiradar.devices.registry"), List.of());
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        assertDoesNotThrow(() -> service.require(principal, List.of(Catalog.LIVE_VIEW)));
        GovernanceException e = refused(() -> service.require(principal, List.of(Catalog.REPORTS_VIEW)));
        assertEquals(GovernanceException.NOT_ENTITLED, e.getCode());
        assertEquals(Catalog.REPORTS_VIEW, e.getPermission());
    }

    @Test
    public void moduleSwitchedOffRemovesItsFeaturesEvenWhenTheFeatureIsOn() throws Exception {
        commercialBody = commercial(TENANT_A, "ACTIVE", List.of(APP),
                List.of("optiradar.tracking.live", "optiradar.devices.registry"), List.of("optiradar.tracking"));
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        assertEquals(GovernanceException.NOT_ENTITLED,
                refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW))).getCode());
        assertDoesNotThrow(() -> service.require(principal, List.of(Catalog.DEVICES_VIEW)));
    }

    @Test
    public void unknownTenantAtOptiNexusIsNotEntitled() throws Exception {
        commercialReply = FakeNexus.Reply.error(404, "NOT_FOUND", "Tenant not found");
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        assertEquals(GovernanceException.NOT_ENTITLED,
                refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW))).getCode());
    }

    @Test
    public void accessEndedAtOptiNexusEndsTheSessionWith401() throws Exception {
        for (String reason : List.of("USER_NOT_ACTIVE", "USER_NOT_FOUND", "TENANT_NOT_ACTIVE", "TENANT_NOT_FOUND",
                "APPLICATION_NOT_ACTIVE")) {
            permissionsBody = grants(SUBJECT_1, TENANT_A, false, reason, 300);
            GovernanceService service = service();
            GovernedPrincipal principal = service.principal(addTenantUser("u-" + reason, SUBJECT_1, groupA).getId());

            GovernanceException e = refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW)));

            assertEquals(401, e.getStatus(), reason);
            assertEquals(GovernanceException.ACCESS_REVOKED, e.getCode(), reason);
            assertTrue(e.endsSessions(), reason);
        }
    }

    @Test
    public void otherRefusalsAre403AndKeepTheSession() throws Exception {
        permissionsBody = grants(SUBJECT_1, TENANT_A, false, "NO_MEMBERSHIP_OR_ROLE", 300);
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        GovernanceException e = refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW)));

        assertEquals(403, e.getStatus());
        assertFalse(e.endsSessions());
        assertEquals(GovernanceException.PERMISSION_DENIED, e.getCode());
    }

    @Test
    public void requireSignedInNeedsAnActiveAccountButNoParticularPermission() throws Exception {
        permissionsBody = grants(SUBJECT_1, TENANT_A, true, null, 300);
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        assertDoesNotThrow(() -> service.requireSignedIn(principal));

        permissionsBody = grants(SUBJECT_1, TENANT_A, false, "USER_NOT_ACTIVE", 300);
        service.invalidateAll();
        assertEquals(401, refused(() -> service.requireSignedIn(principal)).getStatus());
    }

    @Test
    public void operatorPassesAndOtherKindsNeverPassRequire() {
        GovernanceService service = service();

        assertDoesNotThrow(() -> service.require(GovernedPrincipal.operator(1), List.of(Catalog.COMMANDS_SEND)));
        assertEquals(403, refused(() -> service.require(GovernedPrincipal.integration(2),
                List.of(Catalog.DEVICES_VIEW))).getStatus());
        assertEquals("X", refused(() -> service.require(GovernedPrincipal.denied(3, "X"),
                List.of(Catalog.DEVICES_VIEW))).getCode());
        assertTrue(nexus.calls().isEmpty());
    }

    @Test
    public void usersOfDifferentTenantsNeverShareGrants() throws Exception {
        GovernanceService service = service();
        permissionsBody = grants(SUBJECT_1, TENANT_A, true, null, 300, Catalog.LIVE_VIEW);
        GovernedPrincipal a = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());
        assertDoesNotThrow(() -> service.require(a, List.of(Catalog.LIVE_VIEW)));

        // Bob is in tenant B and holds nothing there; Alice's cached answer must not leak to him.
        permissionsBody = grants(SUBJECT_2, TENANT_B, true, null, 300);
        commercialBody = commercial(TENANT_B, "ACTIVE", List.of(APP), List.of("optiradar.tracking.live"), List.of());
        GovernedPrincipal b = service.principal(addTenantUser("bob", SUBJECT_2, groupB).getId());

        assertEquals(GovernanceException.PERMISSION_DENIED,
                refused(() -> service.require(b, List.of(Catalog.LIVE_VIEW))).getCode());
        assertEquals(2, nexus.calls("/api/v1/authorization/effective-permissions").size());
        // Bob is refused on his grants before entitlements are even asked: only Alice's tenant was looked up
        assertEquals(1, nexus.calls("/api/v1/tenants/").size());
        assertTrue(nexus.calls("/api/v1/tenants/").get(0).path().contains(TENANT_A));
    }

    // ---------------------------------------------------------------------------------------------------------
    // Cache

    @Test
    public void answersAreReusedWithinTheTtlAndFetchedAgainAfterIt() throws Exception {
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        service.require(principal, List.of(Catalog.LIVE_VIEW));
        service.require(principal, List.of(Catalog.DEVICES_VIEW));
        clock.addAndGet(TimeUnit.SECONDS.toMillis(299));
        service.require(principal, List.of(Catalog.LIVE_VIEW));
        assertEquals(1, nexus.calls("/api/v1/authorization/effective-permissions").size());
        assertEquals(1, nexus.calls("/api/v1/tenants/").size());

        clock.addAndGet(TimeUnit.SECONDS.toMillis(2));
        service.require(principal, List.of(Catalog.LIVE_VIEW));
        assertEquals(2, nexus.calls("/api/v1/authorization/effective-permissions").size());
        assertEquals(2, nexus.calls("/api/v1/tenants/").size());
    }

    @Test
    public void ttlNeverExceedsFiveMinutesWhateverIsConfiguredOrAnswered() throws Exception {
        Config config = config();
        config.setString(Keys.GOVERNANCE_TTL, "3600");
        permissionsBody = grants(SUBJECT_1, TENANT_A, true, null, 900, Catalog.LIVE_VIEW);
        GovernanceService service = service(config);
        assertEquals(300, service.ttlSeconds());
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        service.require(principal, List.of(Catalog.LIVE_VIEW));
        clock.addAndGet(TimeUnit.SECONDS.toMillis(301));
        service.require(principal, List.of(Catalog.LIVE_VIEW));

        assertEquals(2, nexus.calls("/api/v1/authorization/effective-permissions").size());
    }

    @Test
    public void aShorterLifetimeFromOptiNexusWins() throws Exception {
        permissionsBody = grants(SUBJECT_1, TENANT_A, true, null, 10, Catalog.LIVE_VIEW);
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        service.require(principal, List.of(Catalog.LIVE_VIEW));
        clock.addAndGet(TimeUnit.SECONDS.toMillis(11));
        service.require(principal, List.of(Catalog.LIVE_VIEW));

        assertEquals(2, nexus.calls("/api/v1/authorization/effective-permissions").size());
    }

    @Test
    public void aDenialIsKeptOnlyThirtySeconds() throws Exception {
        permissionsBody = grants(SUBJECT_1, TENANT_A, false, "NO_MEMBERSHIP_OR_ROLE", 300);
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());
        refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW)));

        permissionsBody = grants(SUBJECT_1, TENANT_A, true, null, 300, Catalog.LIVE_VIEW);
        refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW)));
        clock.addAndGet(TimeUnit.SECONDS.toMillis(31));

        assertDoesNotThrow(() -> service.require(principal, List.of(Catalog.LIVE_VIEW)));
    }

    @Test
    public void invalidateForgetsOneUserAndInvalidateAllEverything() throws Exception {
        GovernanceService service = service();
        User user = addTenantUser("alice", SUBJECT_1, groupA);
        GovernedPrincipal principal = service.principal(user.getId());
        service.require(principal, List.of(Catalog.LIVE_VIEW));

        permissionsBody = grants(SUBJECT_1, TENANT_A, true, null, 300);
        service.invalidate(user.getId());
        assertEquals(GovernanceException.PERMISSION_DENIED,
                refused(() -> service.require(service.principal(user.getId()), List.of(Catalog.LIVE_VIEW))).getCode());
        assertEquals(2, nexus.calls("/api/v1/authorization/effective-permissions").size());
        assertEquals(1, nexus.calls("/api/v1/tenants/").size(), "entitlements are per tenant, not per user");

        permissionsBody = grants(SUBJECT_1, TENANT_A, true, null, 300, Catalog.LIVE_VIEW);
        service.invalidateAll();
        assertDoesNotThrow(() -> service.require(service.principal(user.getId()), List.of(Catalog.LIVE_VIEW)));
        assertEquals(2, nexus.calls("/api/v1/tenants/").size());
    }

    @Test
    public void lifecycleChangesDropCachedGrants() throws Exception {
        GovernanceService service = service();
        User user = addTenantUser("alice", SUBJECT_1, groupA);
        service.require(service.principal(user.getId()), List.of(Catalog.LIVE_VIEW));

        lifecycle.endSessions(storage.getObject(User.class, new Request(
                new Columns.All(), new Condition.Equals("id", user.getId()))));
        service.require(service.principal(user.getId()), List.of(Catalog.LIVE_VIEW));

        assertEquals(2, nexus.calls("/api/v1/authorization/effective-permissions").size());
    }

    @Test
    public void concurrentRequestsShareOneQuestionToOptiNexus() throws Exception {
        nexus.setDelayMillis(150);
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                service.require(principal, List.of(Catalog.LIVE_VIEW));
                return null;
            }));
        }
        start.countDown();
        for (Future<?> future : futures) {
            future.get(10, TimeUnit.SECONDS);
        }
        pool.shutdownNow();

        assertEquals(1, nexus.calls("/api/v1/authorization/effective-permissions").size());
        assertEquals(1, nexus.calls("/api/v1/tenants/").size());
    }

    // ---------------------------------------------------------------------------------------------------------
    // Outage: fail closed, never widen

    @Test
    public void whenOptiNexusIsDownAccessIsRefusedWithRetryAfterAndNoFallback() throws Exception {
        permissionsReply = FakeNexus.Reply.error(503, "UNAVAILABLE", "down");
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        GovernanceException e = refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW)));

        assertEquals(503, e.getStatus());
        assertEquals(GovernanceException.UNAVAILABLE, e.getCode());
        assertTrue(e.getRetryAfterSeconds() >= 1);
        assertFalse(e.endsSessions(), "an outage must not log anybody out");
    }

    @Test
    public void whileOptiNexusIsDownFurtherRequestsFailFastAndRecoveryIsAutomatic() throws Exception {
        permissionsReply = FakeNexus.Reply.error(503, "UNAVAILABLE", "down").withHeader("Retry-After", "17");
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        GovernanceException first = refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW)));
        assertEquals(17, first.getRetryAfterSeconds());
        int callsAfterFirst = nexus.calls("/api/v1/authorization/effective-permissions").size();
        refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW)));
        assertEquals(callsAfterFirst, nexus.calls("/api/v1/authorization/effective-permissions").size(),
                "no stampede while OptiNexus is down");

        permissionsReply = null;
        clock.addAndGet(TimeUnit.SECONDS.toMillis(18));
        assertDoesNotThrow(() -> service.require(principal, List.of(Catalog.LIVE_VIEW)));
    }

    @Test
    public void tooManyRequestsHonoursRetryAfter() throws Exception {
        permissionsReply = FakeNexus.Reply.error(429, "RATE_LIMITED", "slow down").withHeader("Retry-After", "42");
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        GovernanceException e = refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW)));

        assertEquals(503, e.getStatus());
        assertEquals(42, e.getRetryAfterSeconds());
    }

    @Test
    public void grantsAreServedWithinTheirLifetimeDuringAnOutageButNeverAfterIt() throws Exception {
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());
        service.require(principal, List.of(Catalog.LIVE_VIEW));

        permissionsReply = FakeNexus.Reply.error(500, "SERVER_ERROR", "down");
        commercialReply = FakeNexus.Reply.error(500, "SERVER_ERROR", "down");
        clock.addAndGet(TimeUnit.SECONDS.toMillis(200));
        assertDoesNotThrow(() -> service.require(principal, List.of(Catalog.LIVE_VIEW)));

        clock.addAndGet(TimeUnit.SECONDS.toMillis(101));
        GovernanceException e = refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW)));
        assertEquals(503, e.getStatus());
        assertEquals(GovernanceException.UNAVAILABLE, e.getCode());
        assertFalse(service.allows(principal.userId(), Catalog.LIVE_VIEW));
    }

    @Test
    public void unreachableOptiNexusIsTreatedAsUnavailable() throws Exception {
        Config config = config();
        config.setString(Keys.OPTINEXUS_BASE_URL, "http://127.0.0.1:1");
        GovernanceService service = service(config);
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        assertEquals(503, refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW))).getStatus());
    }

    @Test
    public void notConfiguredOptiNexusRefusesTenantUsersAndStillStarts() throws Exception {
        Config config = config();
        config.setString(Keys.OPTINEXUS_CLIENT_SECRET, "");
        GovernanceService service = service(config);
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        assertEquals(503, refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW))).getStatus());
        assertDoesNotThrow(() -> service.require(GovernedPrincipal.operator(1), List.of(Catalog.LIVE_VIEW)));
    }

    @Test
    public void rejectedServiceAccountIsAnOutageNotAVerdictAboutTheUser() throws Exception {
        permissionsReply = FakeNexus.Reply.error(403, "SERVICE_ACCOUNT_NOT_BOUND", "not bound");
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        GovernanceException e = refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW)));

        assertEquals(503, e.getStatus());
        assertFalse(e.endsSessions());
    }

    @Test
    public void refusedTokenIsAnOutage() throws Exception {
        nexus.setTokenStatus(401);
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        assertEquals(503, refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW))).getStatus());
    }

    @Test
    public void answerAboutAnotherUserOrTenantIsNeverTrusted() throws Exception {
        permissionsBody = grants(SUBJECT_2, TENANT_A, true, null, 300, Catalog.LIVE_VIEW, Catalog.COMMANDS_SEND);
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());
        assertEquals(503, refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW))).getStatus());

        permissionsBody = grants(SUBJECT_1, TENANT_B, true, null, 300, Catalog.LIVE_VIEW);
        service.invalidateAll();
        clock.addAndGet(TimeUnit.SECONDS.toMillis(60));
        assertEquals(503, refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW))).getStatus());
    }

    @Test
    public void entitlementsOfAnotherTenantAreNeverTrusted() throws Exception {
        commercialBody = commercial(TENANT_B, "ACTIVE", List.of(APP), List.of("optiradar.tracking.live"), List.of());
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        assertEquals(503, refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW))).getStatus());
    }

    @Test
    public void answerInAnUnknownSchemaIsNotTrusted() throws Exception {
        permissionsBody = permissionsBody.replace("\"1.0\"", "\"2.0\"");
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        assertEquals(503, refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW))).getStatus());
    }

    @Test
    public void garbageFromOptiNexusIsNeverAnAllow() throws Exception {
        permissionsReply = FakeNexus.Reply.raw(200, "<html>proxy error</html>");
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        assertEquals(503, refused(() -> service.require(principal, List.of(Catalog.LIVE_VIEW))).getStatus());
    }

    // ---------------------------------------------------------------------------------------------------------
    // Background work, context, sign-in

    @Test
    public void backgroundJobsAreAllowedOnlyWhenTheUserHoldsThePermissionNow() throws Exception {
        GovernanceService service = service();
        User user = addTenantUser("alice", SUBJECT_1, groupA);

        assertTrue(service.allows(user.getId(), Catalog.LIVE_VIEW));
        assertFalse(service.allows(user.getId(), Catalog.REPORTS_SCHEDULE));
        assertFalse(service.allows(9999, Catalog.LIVE_VIEW));
        assertTrue(service.allows(addUser("admin", true, false).getId(), Catalog.REPORTS_SCHEDULE));
    }

    @Test
    public void backgroundJobsAreAllowedWhenGovernanceIsOff() throws Exception {
        Config config = config();
        config.setString(Keys.GOVERNANCE_ENABLE, "false");
        GovernanceService service = service(config);

        assertFalse(service.enabled());
        assertTrue(service.allows(12345, Catalog.REPORTS_SCHEDULE));
        assertTrue(nexus.calls().isEmpty());
    }

    @Test
    public void contextListsOnlyGrantedAndEntitledPermissions() throws Exception {
        commercialBody = commercial(TENANT_A, "ACTIVE", List.of(APP),
                List.of("optiradar.tracking.live", "optiradar.devices.registry"), List.of());
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        GovernanceService.Context context = service.context(principal);

        assertTrue(context.governed());
        assertEquals("central", context.kind());
        assertEquals(TENANT_A, context.tenantId());
        assertEquals(List.of(Catalog.DEVICES_VIEW, Catalog.LIVE_VIEW).stream().sorted().toList(),
                context.permissions().stream().sorted().toList());
        assertFalse(context.permissions().contains(Catalog.REPORTS_VIEW), "granted but not entitled");
        assertTrue(context.applicationEntitled());
        assertTrue(context.ttlSeconds() > 0 && context.ttlSeconds() <= 300);
        assertEquals(Catalog.REVISION, context.manifestRevision());
        assertNotNull(context.capabilities());
    }

    @Test
    public void contextOfAnUnentitledTenantHasNoPermissions() throws Exception {
        commercialBody = commercial(TENANT_A, "ACTIVE", List.of("optifleet"), List.of(), List.of());
        GovernanceService service = service();
        GovernedPrincipal principal = service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());

        GovernanceService.Context context = service.context(principal);

        assertFalse(context.applicationEntitled());
        assertTrue(context.permissions().isEmpty());
        assertTrue(context.capabilities().isEmpty());
    }

    @Test
    public void contextOfAnOperatorIsTheWholeCatalog() {
        GovernanceService.Context context = service().context(GovernedPrincipal.operator(1));

        assertEquals("operator", context.kind());
        assertEquals(Catalog.permissions().size(), context.permissions().size());
    }

    @Test
    public void signInIsAdmittedForATenantUserAndFetchesTheGrantsOnce() throws Exception {
        GovernanceService service = service();
        User user = addTenantUser("alice", SUBJECT_1, groupA);

        service.admit(user);

        assertEquals(1, nexus.calls("/api/v1/authorization/effective-permissions").size());
        service.require(service.principal(user.getId()), List.of(Catalog.LIVE_VIEW));
        assertEquals(1, nexus.calls("/api/v1/authorization/effective-permissions").size());
    }

    @Test
    public void signInIsRefusedForAccountsThatCannotBeTenantUsers() throws Exception {
        GovernanceService service = service();

        assertThrows(GeneralSecurityException.class, () -> service.admit(addUser("local", false, false)));
        assertThrows(GeneralSecurityException.class, () -> service.admit(addUser("root", true, false)));
        assertThrows(GeneralSecurityException.class, () -> service.admit(addTenantUser("two", SUBJECT_2, groupA,
                groupB)));
    }

    @Test
    public void signInIsRefusedWhenOptiNexusSaysAccessEnded() throws Exception {
        permissionsBody = grants(SUBJECT_1, TENANT_A, false, "USER_NOT_ACTIVE", 300);
        GovernanceService service = service();

        assertThrows(GeneralSecurityException.class, () -> service.admit(addTenantUser("alice", SUBJECT_1, groupA)));
    }

    @Test
    public void signInStillWorksWhenOptiNexusCannotBeReachedForAMoment() throws Exception {
        permissionsReply = FakeNexus.Reply.error(503, "UNAVAILABLE", "down");
        GovernanceService service = service();
        User user = addTenantUser("alice", SUBJECT_1, groupA);

        assertDoesNotThrow(() -> service.admit(user));
        // ... but nothing is allowed until the grants are known
        assertEquals(503, refused(() -> service.require(service.principal(user.getId()),
                List.of(Catalog.LIVE_VIEW))).getStatus());
    }

    @Test
    public void endingSessionsIsRateLimited() throws Exception {
        GovernanceService service = service();
        User user = addTenantUser("alice", SUBJECT_1, groupA);

        service.endSessions(user.getId());
        long first = storage.getObject(User.class, new Request(new Columns.All(),
                new Condition.Equals("id", user.getId()))).getLong(OpenIdLifecycle.SESSIONS_NOT_BEFORE);
        assertTrue(first > 0);

        service.endSessions(user.getId());
        long second = storage.getObject(User.class, new Request(new Columns.All(),
                new Condition.Equals("id", user.getId()))).getLong(OpenIdLifecycle.SESSIONS_NOT_BEFORE);
        assertEquals(first, second, "a denied client that keeps calling does not rewrite the user each time");

        clock.addAndGet(TimeUnit.SECONDS.toMillis(61));
        service.endSessions(user.getId());
        long third = storage.getObject(User.class, new Request(new Columns.All(),
                new Condition.Equals("id", user.getId()))).getLong(OpenIdLifecycle.SESSIONS_NOT_BEFORE);
        assertTrue(third > second);
    }

}
