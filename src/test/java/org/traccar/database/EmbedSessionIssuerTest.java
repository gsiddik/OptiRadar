package org.traccar.database;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.traccar.api.signature.TokenManager;
import org.traccar.config.Config;
import org.traccar.helper.LogAction;
import org.traccar.model.Group;
import org.traccar.model.Permission;
import org.traccar.model.User;
import org.traccar.session.cache.CacheManager;
import org.traccar.storage.MemoryStorage;
import org.traccar.storage.Storage;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Request;

import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class EmbedSessionIssuerTest {

    private static final String TENANT_A = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";
    private static final String TENANT_B = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c02";

    private Storage storage;
    private EmbedSessionIssuer issuer;

    @BeforeEach
    public void setUp() throws Exception {
        storage = new MemoryStorage();
        CacheManager cacheManager = mock(CacheManager.class);
        TokenManager tokenManager = mock(TokenManager.class);
        when(tokenManager.generateToken(anyLong(), any(Date.class))).thenReturn("token");
        OpenIdTenantLinker linker = new OpenIdTenantLinker(new Config(), storage, cacheManager, mock(LogAction.class));
        issuer = new EmbedSessionIssuer(storage, cacheManager, linker, tokenManager);
    }

    private Group addGroup(String tenantId) throws Exception {
        Group group = new Group();
        group.setName("Tenant " + tenantId);
        group.set("optinexusTenantId", tenantId);
        group.setId(storage.addObject(group, new Request(new Columns.Exclude("id"))));
        return group;
    }

    @Test
    public void createsATemporaryReadOnlyUserLimitedToTheTenantGroup() throws Exception {
        Group a = addGroup(TENANT_A);
        addGroup(TENANT_B);

        EmbedSessionIssuer.Session session = issuer.issue(TENANT_A, 600);

        assertEquals("token", session.token());
        long ttl = session.expiration().getTime() - System.currentTimeMillis();
        assertTrue(ttl > 500_000 && ttl <= 600_000);

        List<User> users = storage.getObjects(User.class, new Request(new Columns.All()));
        assertEquals(1, users.size());
        User user = users.get(0);
        assertTrue(user.getTemporary());
        assertTrue(user.getReadonly());
        assertTrue(user.getLimitCommands());
        assertTrue(user.getDisableReports());

        List<Permission> permissions = storage.getPermissions(User.class, user.getId(), Group.class, 0);
        assertEquals(1, permissions.size());
        assertEquals(a.getId(), permissions.get(0).getPropertyId());
    }

    @Test
    public void capsTheLifetimeAtFifteenMinutes() throws Exception {
        addGroup(TENANT_A);

        EmbedSessionIssuer.Session session = issuer.issue(TENANT_A, 86_400);

        assertTrue(session.expiration().getTime() - System.currentTimeMillis() <= 900_000);
    }

    @Test
    public void refusesAnUnknownTenant() throws Exception {
        addGroup(TENANT_A);

        assertThrows(GeneralSecurityException.class, () -> issuer.issue(TENANT_B, 600));
        assertThrows(GeneralSecurityException.class, () -> issuer.issue(null, 600));
        assertTrue(storage.getObjects(User.class, new Request(new Columns.All())).isEmpty());
    }

    @Test
    public void removesExpiredEmbedUsersButNotOtherTemporaryOnes() throws Exception {
        addGroup(TENANT_A);
        User expired = new User();
        expired.setEmail("embed:1:old");
        expired.setTemporary(true);
        expired.setExpirationTime(new Date(System.currentTimeMillis() - 1000));
        expired.setId(storage.addObject(expired, new Request(new Columns.Exclude("id"))));
        User share = new User();
        share.setEmail("owner@example.test:device123");
        share.setTemporary(true);
        share.setExpirationTime(new Date(System.currentTimeMillis() - 1000));
        share.setId(storage.addObject(share, new Request(new Columns.Exclude("id"))));

        issuer.issue(TENANT_A, 600);

        List<User> users = storage.getObjects(User.class, new Request(new Columns.All()));
        assertEquals(2, users.size());
        assertFalse(users.stream().anyMatch(u -> "embed:1:old".equals(u.getEmail())));
    }
}
