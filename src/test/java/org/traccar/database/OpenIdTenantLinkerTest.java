package org.traccar.database;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

public class OpenIdTenantLinkerTest {

    private static final String TENANT_A = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";
    private static final String TENANT_B = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c02";

    private Storage storage;
    private CacheManager cacheManager;
    private OpenIdTenantLinker linker;

    @BeforeEach
    public void setUp() {
        storage = new MemoryStorage();
        cacheManager = mock(CacheManager.class);
        linker = new OpenIdTenantLinker(new Config(), storage, cacheManager, mock(LogAction.class));
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

    private User addUser() throws Exception {
        User user = new User();
        user.setEmail("driver@example.test");
        user.setId(storage.addObject(user, new Request(new Columns.Exclude("id"))));
        return user;
    }

    private List<Long> groupsOf(User user) throws Exception {
        return storage.getPermissions(User.class, user.getId(), Group.class, 0).stream()
                .map(Permission::getPropertyId).sorted().toList();
    }

    @Test
    public void findsTheGroupOfTheTenantIgnoringCaseAndSpaces() throws Exception {
        Group a = addGroup("Tenant A", TENANT_A);
        addGroup("Tenant B", TENANT_B);
        addGroup("Admin only", null);

        assertEquals(a.getId(), linker.findGroup("  " + TENANT_A.toUpperCase() + " ").getId());
    }

    @Test
    public void rejectsMissingUnknownAndAmbiguousTenants() throws Exception {
        addGroup("Tenant A", TENANT_A);
        addGroup("Tenant A again", TENANT_A);

        assertThrows(GeneralSecurityException.class, () -> linker.findGroup(null));
        assertThrows(GeneralSecurityException.class, () -> linker.findGroup("  "));
        assertThrows(GeneralSecurityException.class, () -> linker.findGroup(TENANT_B));
        assertThrows(GeneralSecurityException.class, () -> linker.findGroup(TENANT_A));
    }

    @Test
    public void linksTheUserToTheTenantGroupAndNothingElse() throws Exception {
        Group a = addGroup("Tenant A", TENANT_A);
        addGroup("Tenant B", TENANT_B);
        User user = addUser();

        linker.link(mock(jakarta.servlet.http.HttpServletRequest.class), user, a);

        assertEquals(List.of(a.getId()), groupsOf(user));
        verify(cacheManager).invalidatePermission(eq(true), eq(User.class), eq(user.getId()), eq(Group.class), eq(a.getId()), eq(true));
    }

    @Test
    public void movesTheUserOutOfAnotherTenantButKeepsOtherGroups() throws Exception {
        Group a = addGroup("Tenant A", TENANT_A);
        Group b = addGroup("Tenant B", TENANT_B);
        Group shared = addGroup("Not a tenant", null);
        User user = addUser();
        storage.addPermission(new Permission(User.class, user.getId(), Group.class, b.getId()));
        storage.addPermission(new Permission(User.class, user.getId(), Group.class, shared.getId()));

        linker.link(mock(jakarta.servlet.http.HttpServletRequest.class), user, a);

        assertEquals(List.of(a.getId(), shared.getId()).stream().sorted().toList(), groupsOf(user));
        verify(cacheManager).invalidatePermission(eq(true), eq(User.class), eq(user.getId()), eq(Group.class), eq(b.getId()), eq(false));
    }

    @Test
    public void linkingTwiceChangesNothing() throws Exception {
        Group a = addGroup("Tenant A", TENANT_A);
        User user = addUser();
        var request = mock(jakarta.servlet.http.HttpServletRequest.class);

        linker.link(request, user, a);
        linker.link(request, user, a);

        assertEquals(List.of(a.getId()), groupsOf(user));
        verify(cacheManager, org.mockito.Mockito.times(1))
                .invalidatePermission(anyBoolean(), eq(User.class), anyLong(), eq(Group.class), anyLong(), anyBoolean());
        verify(cacheManager, never())
                .invalidatePermission(anyBoolean(), eq(User.class), anyLong(), eq(Group.class), anyLong(), eq(false));
    }
}
