package org.traccar.governance;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
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
import org.traccar.storage.query.Request;

import jakarta.ws.rs.client.ClientBuilder;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

/**
 * A fake OptiNexus (documented JSON), an in-memory store with two tenants and the real governance classes wired the way
 * the server wires them, for tests of everything that talks to OptiNexus.
 */
public abstract class GovernanceTestBase {

    protected static final String TENANT_A = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";
    protected static final String TENANT_B = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c02";
    protected static final String SUBJECT_1 = "5d3a7f9e-1b2c-4d5e-8f60-7a8b9c0d1e01";
    protected static final String SUBJECT_2 = "5d3a7f9e-1b2c-4d5e-8f60-7a8b9c0d1e02";
    protected static final String ISSUER = "https://nexus.example.test";
    protected static final String APP = "optiradar";

    protected final AtomicLong clock = new AtomicLong(System.currentTimeMillis());

    protected FakeNexus nexus;
    protected Storage storage;
    protected OpenIdLifecycle lifecycle;
    protected NexusClient nexusClient;
    protected Group groupA;
    protected Group groupB;

    // What the fake OptiNexus answers; tests change these.
    protected volatile String permissionsBody;
    protected volatile String commercialBody;
    protected volatile FakeNexus.Reply permissionsReply;
    protected volatile FakeNexus.Reply commercialReply;

    @BeforeEach
    public void setUpNexus() throws Exception {
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
    public void tearDownNexus() {
        nexus.close();
    }

    protected String grants(String subject, String tenant, boolean allowed, String reason, int ttl, String... keys) {
        return FakeNexus.effectivePermissions(subject, tenant, APP, allowed, reason, ttl, keys);
    }

    protected String commercial(
            String tenant, String status, List<String> applications, List<String> on, List<String> off) {
        return FakeNexus.commercialContext(tenant, status, applications, on, off);
    }

    protected Group addGroup(String name, String tenantId) throws Exception {
        Group group = new Group();
        group.setName(name);
        if (tenantId != null) {
            group.set("optinexusTenantId", tenantId);
        }
        group.setId(storage.addObject(group, new Request(new Columns.Exclude("id"))));
        return group;
    }

    protected Config config() {
        Config config = new Config();
        config.setString(Keys.GOVERNANCE_ENABLE, "true");
        config.setString(Keys.OPENID_TENANT_CLAIM, "tenant_id");
        config.setString(Keys.OPTINEXUS_BASE_URL, nexus.baseUrl());
        config.setString(Keys.OPTINEXUS_CLIENT_ID, "radar-client");
        config.setString(Keys.OPTINEXUS_CLIENT_SECRET, "radar-secret");
        return config;
    }

    protected GovernanceService service() {
        return service(config());
    }

    protected GovernanceService service(Config config) {
        NexusClient client = nexusClient = new NexusClient(config, ClientBuilder.newClient(), new ObjectMapper()) {
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

    protected User addUser(String login, boolean administrator, boolean readonly) throws Exception {
        User user = new User();
        user.setLogin(login);
        user.setEmail(login + "@example.test");
        user.setAdministrator(administrator);
        user.setReadonly(readonly);
        user.setId(storage.addObject(user, new Request(new Columns.Exclude("id"))));
        return user;
    }

    protected User addTenantUser(String login, String subject, Group... groups) throws Exception {
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

    protected GovernanceException refused(Runnable action) {
        return assertThrows(GovernanceException.class, action::run);
    }

}
