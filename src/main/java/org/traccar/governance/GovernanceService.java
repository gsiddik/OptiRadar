package org.traccar.governance;

import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.api.security.ServiceAccountUser;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.database.OpenIdIdentities;
import org.traccar.database.OpenIdLifecycle;
import org.traccar.database.OpenIdTenantLinker;
import org.traccar.model.OpenIdIdentity;
import org.traccar.model.User;
import org.traccar.storage.Storage;
import org.traccar.storage.StorageException;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * The one place that decides what a user may do in OptiRadar while governance is enabled. OptiNexus is the authority:
 * the user's permissions come from {@code POST /authorization/effective-permissions} and the tenant's modules and
 * features from the tenant's commercial context. Both answers are kept for at most five minutes (and no longer than
 * the lifetime OptiNexus states); after that they are fetched again, and when OptiNexus cannot be reached the answer is
 * "denied, try later". There is no local fallback and nothing is ever widened: native flags and device/group links
 * only restrict what OptiNexus granted.
 */
@Singleton
public class GovernanceService {

    private static final Logger LOGGER = LoggerFactory.getLogger(GovernanceService.class);

    public static final String SCOPE_AUTHORIZATION = "authorization.check";
    public static final String SCOPE_COMMERCIAL = "commercial.read";

    private static final int MAX_TTL_SECONDS = 300;
    private static final int DENY_TTL_SECONDS = 30;
    private static final int PRINCIPAL_TTL_SECONDS = 30;
    private static final long MIN_REFRESH_MILLIS = 5000;
    private static final int MAX_CACHE_ENTRIES = 20000;
    private static final int LOCK_STRIPES = 32;
    private static final Pattern UUID = Pattern.compile(
            "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Set<String> REVOKED_REASONS = Set.of(
            "USER_NOT_ACTIVE", "USER_NOT_FOUND", "TENANT_NOT_ACTIVE", "TENANT_NOT_FOUND", "APPLICATION_NOT_ACTIVE");

    /**
     * What OptiNexus said a user holds in one tenant.
     */
    record Grants(String reason, boolean allowed, Set<String> permissions, long expires) {
    }

    /**
     * What a tenant bought for OptiRadar.
     */
    record Entitlements(boolean applicationEnabled, Set<String> enabled, Set<String> disabled, long expires) {
    }

    /**
     * What a switcher may show, and when OptiNexus was asked.
     */
    public record Products(
            ProductContext.Tenant tenant, List<ProductContext.Product> products, long expiresAt, int ttlSeconds) {
    }

    private record CachedProducts(Products products, long fetched, long expires) {
    }

    private record CachedPrincipal(
            GovernedPrincipal principal, boolean administrator, boolean readonly, long expires) {
    }

    /**
     * What the web app needs to know to draw the screen: it only represents these decisions.
     */
    public record Context(
            boolean governed, String kind, String tenantId, List<String> permissions, List<String> capabilities,
            boolean applicationEntitled, long expiresAt, int ttlSeconds, String manifestRevision) {
    }

    private final boolean enabled;
    private final String applicationCode;
    private final int ttlSeconds;
    private final Storage storage;
    private final NexusClient nexus;
    private final OpenIdIdentities identities;
    private final OpenIdTenantLinker tenantLinker;
    private final OpenIdLifecycle lifecycle;
    private final Set<String> integrationUsers = new HashSet<>();

    private final Map<String, Grants> grantCache = new ConcurrentHashMap<>();
    private final Map<String, Entitlements> entitlementCache = new ConcurrentHashMap<>();
    private final Map<String, CachedProducts> productCache = new ConcurrentHashMap<>();
    private final Map<Long, CachedPrincipal> principals = new ConcurrentHashMap<>();
    private final Map<Long, String> grantKeys = new ConcurrentHashMap<>();
    private final Object[] locks = new Object[LOCK_STRIPES];

    private volatile long unavailableUntil;
    private volatile int unavailableRetry;

    @Inject
    public GovernanceService(
            Config config, Storage storage, NexusClient nexus, OpenIdIdentities identities,
            OpenIdTenantLinker tenantLinker, OpenIdLifecycle lifecycle) {
        this.enabled = config.getBoolean(Keys.GOVERNANCE_ENABLE);
        this.applicationCode = config.getString(Keys.GOVERNANCE_APPLICATION_CODE);
        this.ttlSeconds = Math.max(1, Math.min(MAX_TTL_SECONDS, config.getInteger(Keys.GOVERNANCE_TTL)));
        this.storage = storage;
        this.nexus = nexus;
        this.identities = identities;
        this.tenantLinker = tenantLinker;
        this.lifecycle = lifecycle;
        for (int i = 0; i < locks.length; i++) {
            locks[i] = new Object();
        }
        lifecycle.addListener(this::invalidate);
        String list = config.getString(Keys.GOVERNANCE_INTEGRATION_USERS);
        if (list != null) {
            for (String entry : list.split(",")) {
                if (!entry.isBlank()) {
                    integrationUsers.add(entry.trim().toLowerCase(Locale.ROOT));
                }
            }
        }
        if (enabled && !nexus.configured()) {
            LOGGER.error("governance.enable is on but optinexus.baseUrl, optinexus.clientId or optinexus.clientSecret "
                    + "is missing: every tenant user is refused until OptiNexus is configured");
        }
        if (enabled && config.getString(Keys.OPENID_TENANT_CLAIM) == null) {
            LOGGER.error("governance.enable is on but openid.tenantClaim is not set: tenant users cannot be tied "
                    + "to a tenant and are refused");
        }
    }

    protected long now() {
        return System.currentTimeMillis();
    }

    public boolean enabled() {
        return enabled;
    }

    public String applicationCode() {
        return applicationCode;
    }

    public int ttlSeconds() {
        return ttlSeconds;
    }

    // ---------------------------------------------------------------------------------------------------------
    // Who is acting

    public GovernedPrincipal principal(long userId) {
        if (userId == ServiceAccountUser.ID) {
            return GovernedPrincipal.operator(userId);
        }
        try {
            User user = storage.getObject(User.class, new Request(
                    new Columns.All(), new Condition.Equals("id", userId)));
            return user != null
                    ? principal(user) : GovernedPrincipal.denied(userId, GovernanceException.IDENTITY_REQUIRED);
        } catch (StorageException e) {
            LOGGER.warn("Governance cannot load the account of user {}", userId, e);
            throw new GovernanceException(503, GovernanceException.UNAVAILABLE, "Account store unavailable", null,
                    5, false);
        }
    }

    public GovernedPrincipal principal(User user) {
        if (user.getId() == ServiceAccountUser.ID) {
            return GovernedPrincipal.operator(user.getId());
        }
        CachedPrincipal cached = principals.get(user.getId());
        if (cached != null && now() < cached.expires()
                && cached.administrator() == user.getAdministrator() && cached.readonly() == user.getReadonly()) {
            return cached.principal();
        }
        GovernedPrincipal principal;
        try {
            principal = resolve(user);
        } catch (StorageException e) {
            LOGGER.warn("Governance cannot resolve the identity of user {}", user.getId(), e);
            throw new GovernanceException(503, GovernanceException.UNAVAILABLE, "Account store unavailable", null,
                    5, false);
        }
        if (principals.size() > MAX_CACHE_ENTRIES) {
            principals.clear();
        }
        principals.put(user.getId(), new CachedPrincipal(principal, user.getAdministrator(), user.getReadonly(),
                now() + TimeUnit.SECONDS.toMillis(PRINCIPAL_TTL_SECONDS)));
        return principal;
    }

    private GovernedPrincipal resolve(User user) throws StorageException {
        if (user.getAdministrator()) {
            return GovernedPrincipal.operator(user.getId());
        }
        OpenIdIdentity identity = identities.findForUser(user.getId());
        if (identity != null) {
            Set<String> tenants = tenantLinker.tenantsOf(user.getId());
            if (tenants.size() != 1) {
                LOGGER.warn("User {} reaches {} tenants; access is refused", user.getId(), tenants.size());
                return GovernedPrincipal.denied(user.getId(), GovernanceException.TENANT_UNRESOLVED);
            }
            String tenant = tenants.iterator().next();
            String subject = identity.getSubject() != null ? identity.getSubject().toLowerCase(Locale.ROOT) : "";
            if (!UUID.matcher(tenant).matches() || !UUID.matcher(subject).matches()) {
                LOGGER.warn("User {} has a tenant or subject that is not an OptiNexus id", user.getId());
                return GovernedPrincipal.denied(user.getId(), GovernanceException.TENANT_UNRESOLVED);
            }
            return GovernedPrincipal.central(user.getId(), subject, tenant);
        }
        if (user.getReadonly() && isIntegrationUser(user)) {
            return GovernedPrincipal.integration(user.getId());
        }
        return GovernedPrincipal.denied(user.getId(), GovernanceException.IDENTITY_REQUIRED);
    }

    private boolean isIntegrationUser(User user) {
        return user.getEmail() != null && integrationUsers.contains(user.getEmail().trim().toLowerCase(Locale.ROOT))
                || user.getLogin() != null
                && integrationUsers.contains(user.getLogin().trim().toLowerCase(Locale.ROOT));
    }

    // ---------------------------------------------------------------------------------------------------------
    // Decisions

    /**
     * Passes when the principal may use every permission, otherwise throws why not. Operators pass; integration and
     * denied principals never pass here (their routes are decided before).
     */
    public void require(GovernedPrincipal principal, Collection<String> permissions) {
        switch (principal.kind()) {
            case OPERATOR:
                return;
            case CENTRAL:
                break;
            default:
                throw new GovernanceException(403,
                        principal.code() != null ? principal.code() : GovernanceException.IDENTITY_REQUIRED,
                        "This account has no OptiNexus grants", null);
        }
        Grants grants = grants(principal);
        checkGate(grants, permissions.isEmpty() ? null : permissions.iterator().next());
        for (String permission : permissions) {
            if (!grants.permissions().contains(permission) || Catalog.permission(permission).isEmpty()) {
                throw new GovernanceException(403, GovernanceException.PERMISSION_DENIED,
                        "Permission " + permission + " is not granted", permission);
            }
        }
        Entitlements entitlements = entitlements(principal.tenantId());
        if (!entitlements.applicationEnabled()) {
            throw new GovernanceException(403, GovernanceException.NOT_ENTITLED,
                    "The tenant is not entitled to OptiRadar", permissions.isEmpty() ? null
                    : permissions.iterator().next());
        }
        for (String permission : permissions) {
            if (!entitled(entitlements, permission)) {
                throw new GovernanceException(403, GovernanceException.NOT_ENTITLED,
                        "The tenant is not entitled to the feature of " + permission, permission);
            }
        }
    }

    /**
     * The user passes the gate (active, tenant active, application active) but holds no OptiRadar permission at all or
     * is not entitled: used for the routes every signed-in user needs.
     */
    public void requireSignedIn(GovernedPrincipal principal) {
        switch (principal.kind()) {
            case OPERATOR:
                return;
            case CENTRAL:
                break;
            default:
                throw new GovernanceException(403,
                        principal.code() != null ? principal.code() : GovernanceException.IDENTITY_REQUIRED,
                        "This account has no OptiNexus grants", null);
        }
        checkGate(grants(principal), null);
    }

    private void checkGate(Grants grants, String permission) {
        if (grants.allowed()) {
            return;
        }
        if (REVOKED_REASONS.contains(grants.reason())) {
            throw new GovernanceException(401, GovernanceException.ACCESS_REVOKED,
                    "OptiNexus reports the access ended: " + grants.reason(), permission, 0, true);
        }
        throw new GovernanceException(403, GovernanceException.PERMISSION_DENIED,
                "OptiNexus grants nothing for OptiRadar to this user", permission);
    }

    private boolean entitled(Entitlements entitlements, String permission) {
        String capability = Catalog.capabilityOf(permission);
        if (capability == null) {
            return false;
        }
        String module = Catalog.moduleOf(capability);
        if (module != null && entitlements.disabled().contains(module)) {
            return false;
        }
        return entitlements.enabled().contains(capability);
    }

    /**
     * For work done on behalf of a user outside a request (scheduled reports, notifications): true only when the user
     * holds the permission now. Anything that cannot be decided is false; the job skips and says so in the log.
     */
    public boolean allows(long userId, String permission) {
        if (!enabled) {
            return true;
        }
        try {
            GovernedPrincipal principal = principal(userId);
            require(principal, List.of(permission));
            return true;
        } catch (GovernanceException e) {
            if (e.getStatus() == 503) {
                LOGGER.warn("Skipped work for user {}: access cannot be decided now ({})", userId, e.getMessage());
            } else {
                LOGGER.debug("Skipped work for user {}: {}", userId, e.getMessage());
            }
            return false;
        }
    }

    /**
     * The user's effective permissions after entitlements, for the web app. Throws like {@link #require}.
     */
    public Context context(GovernedPrincipal principal) {
        if (principal.kind() == GovernedPrincipal.Kind.OPERATOR) {
            return new Context(true, "operator", null,
                    Catalog.permissions().stream().map(Catalog.Permission::key).toList(),
                    Catalog.capabilities().stream().map(Catalog.Capability::code).toList(),
                    true, 0, 0, Catalog.REVISION);
        }
        requireSignedIn(principal);
        Grants grants = grants(principal);
        Entitlements entitlements = entitlements(principal.tenantId());
        List<String> permissions = new ArrayList<>();
        if (entitlements.applicationEnabled()) {
            for (Catalog.Permission permission : Catalog.permissions()) {
                if (grants.permissions().contains(permission.key()) && entitled(entitlements, permission.key())) {
                    permissions.add(permission.key());
                }
            }
        }
        long expires = Math.min(grants.expires(), entitlements.expires());
        List<String> capabilities = entitlements.applicationEnabled()
                ? entitlements.enabled().stream().filter(code -> Catalog.capability(code).isPresent()).sorted().toList()
                : List.of();
        return new Context(true, "central", principal.tenantId(), permissions, capabilities,
                entitlements.applicationEnabled(), expires, (int) Math.max(0, (expires - now()) / 1000),
                Catalog.REVISION);
    }

    /**
     * The products the signed-in user may open from here (OptiNexus {@code product-context}): only what the tenant
     * subscribes to and the user was assigned, never the governance portal, each with the address that continues the
     * same tenant. Cached for at most five minutes; {@code fresh} asks again (at most once every five seconds per
     * user, so a busy switcher cannot flood OptiNexus). Nothing is listed when OptiNexus cannot answer.
     *
     * <p>When OptiNexus says the user's access ended ({@code allowed=false}) the grants and product cache of the user
     * are dropped, the user's sessions end, and this throws a 401 that ends the browser session too.</p>
     */
    public Products products(GovernedPrincipal principal, boolean fresh) {
        if (principal.kind() == GovernedPrincipal.Kind.OPERATOR) {
            return new Products(null, List.of(), 0, 0);
        }
        requireSignedIn(principal);
        String key = principal.tenantId() + "|" + principal.subject();
        CachedProducts cached = productCache.get(key);
        if (reusable(cached, fresh)) {
            return cached.products();
        }
        synchronized (lock(key)) {
            cached = productCache.get(key);
            if (reusable(cached, fresh)) {
                return cached.products();
            }
            failFastIfDown(now());
            try {
                JsonNode data = nexus.post(SCOPE_AUTHORIZATION, "/api/v1/authorization/product-context",
                        Map.of("user_id", principal.subject(), "tenant_id", principal.tenantId()));
                ProductContext.Decision decision = ProductContext.parse(
                        data, principal.subject(), principal.tenantId(), applicationCode);
                if (!decision.allowed()) {
                    LOGGER.info("OptiNexus ended the access of user {}: {}", principal.userId(),
                            decision.denyReason());
                    productCache.remove(key);
                    invalidate(principal.userId());
                    endSessions(principal.userId());
                    throw new GovernanceException(401, GovernanceException.ACCESS_REVOKED,
                            "OptiNexus reports the access ended: " + decision.denyReason(), null, 0, true);
                }
                int ttl = Math.max(1, Math.min(ttlSeconds, decision.ttlSeconds()));
                long fetched = now();
                long expires = fetched + TimeUnit.SECONDS.toMillis(ttl);
                Products products = new Products(decision.tenant(), decision.products(), expires, ttl);
                if (productCache.size() > MAX_CACHE_ENTRIES) {
                    productCache.clear();
                }
                productCache.put(key, new CachedProducts(products, fetched, expires));
                grantKeys.put(principal.userId(), key);
                return products;
            } catch (NexusClient.UnavailableException e) {
                throw down(e);
            } catch (IllegalArgumentException e) {
                LOGGER.warn("OptiNexus gave a product answer that does not match the request: {}", e.getMessage());
                throw new GovernanceException(503, GovernanceException.UNAVAILABLE, "OptiNexus answered for another "
                        + "subject", null, 30, false);
            } catch (NexusClient.RejectedException e) {
                // Not a decision about the user's access (that is asked per request): list nothing.
                LOGGER.error("OptiNexus refused the product question ({}): check the service account binding "
                        + "and its authorization.check scope", e.getCode());
                throw new GovernanceException(503, GovernanceException.UNAVAILABLE, "OptiNexus refused the product "
                        + "question", null, 30, false);
            }
        }
    }

    private boolean reusable(CachedProducts cached, boolean fresh) {
        long now = now();
        return cached != null && now < cached.expires() && (!fresh || now - cached.fetched() < MIN_REFRESH_MILLIS);
    }

    // ---------------------------------------------------------------------------------------------------------
    // OptiNexus calls

    Object lock(String key) {
        return locks[Math.floorMod(key.hashCode(), LOCK_STRIPES)];
    }

    void failFastIfDown(long now) {
        if (now < unavailableUntil) {
            throw new GovernanceException(503, GovernanceException.UNAVAILABLE, "OptiNexus is not reachable",
                    null, unavailableRetry, false);
        }
    }

    GovernanceException down(NexusClient.UnavailableException e) {
        int retry = Math.max(1, Math.min(120, e.getRetryAfterSeconds()));
        unavailableRetry = retry;
        unavailableUntil = now() + TimeUnit.SECONDS.toMillis(retry);
        LOGGER.warn("OptiNexus did not answer an access question: {}", e.getMessage());
        return new GovernanceException(503, GovernanceException.UNAVAILABLE, "OptiNexus is not reachable",
                null, retry, false);
    }

    private Grants grants(GovernedPrincipal principal) {
        String key = principal.tenantId() + "|" + principal.subject();
        Grants cached = grantCache.get(key);
        if (cached != null && now() < cached.expires()) {
            return cached;
        }
        synchronized (lock(key)) {
            cached = grantCache.get(key);
            if (cached != null && now() < cached.expires()) {
                return cached;
            }
            failFastIfDown(now());
            try {
                JsonNode data = nexus.post(SCOPE_AUTHORIZATION, "/api/v1/authorization/effective-permissions",
                        Map.of("user_id", principal.subject(), "tenant_id", principal.tenantId(),
                                "application_code", applicationCode));
                Grants grants = parseGrants(principal, data);
                if (grantCache.size() > MAX_CACHE_ENTRIES) {
                    grantCache.clear();
                }
                grantCache.put(key, grants);
                grantKeys.put(principal.userId(), key);
                return grants;
            } catch (NexusClient.UnavailableException e) {
                throw down(e);
            } catch (NexusClient.RejectedException e) {
                if (e.getStatus() == 403) {
                    // The service account itself is not accepted for this tenant or application: a setup problem,
                    // not a decision about the user.
                    LOGGER.error("OptiNexus refused the OptiRadar service account for authorization ({}): fix the "
                            + "service account binding", e.getCode());
                    throw down(new NexusClient.UnavailableException(e.getCode(), 30, e));
                }
                Grants denied = new Grants(e.getCode(), false, Set.of(),
                        now() + TimeUnit.SECONDS.toMillis(DENY_TTL_SECONDS));
                grantCache.put(key, denied);
                return denied;
            }
        }
    }

    private Grants parseGrants(GovernedPrincipal principal, JsonNode data) throws NexusClient.UnavailableException {
        if (!"1.0".equals(data.path("schema_version").asText())
                || !principal.subject().equalsIgnoreCase(data.path("user_id").asText())
                || !principal.tenantId().equalsIgnoreCase(data.path("tenant_id").asText())
                || !applicationCode.equals(data.path("application_code").asText())) {
            // The answer is about somebody or something else, or in a format this server does not know.
            throw new NexusClient.UnavailableException("OptiNexus gave an answer for another subject", 30, null);
        }
        boolean allowed = data.path("allowed").asBoolean(false);
        Set<String> permissions = new HashSet<>();
        if (allowed) {
            for (JsonNode entry : data.path("permissions")) {
                String key = entry.path("permission").asText("");
                if (key.startsWith(applicationCode + ".")) {
                    permissions.add(key);
                }
            }
        }
        int ttl = Math.max(1, Math.min(ttlSeconds, data.path("ttl_seconds").asInt(ttlSeconds)));
        if (!allowed) {
            ttl = Math.min(ttl, DENY_TTL_SECONDS);
        }
        String reason = data.hasNonNull("deny_reason") ? data.get("deny_reason").asText() : null;
        return new Grants(reason, allowed, Set.copyOf(permissions), now() + TimeUnit.SECONDS.toMillis(ttl));
    }

    private Entitlements entitlements(String tenantId) {
        Entitlements cached = entitlementCache.get(tenantId);
        if (cached != null && now() < cached.expires()) {
            return cached;
        }
        synchronized (lock(tenantId)) {
            cached = entitlementCache.get(tenantId);
            if (cached != null && now() < cached.expires()) {
                return cached;
            }
            failFastIfDown(now());
            try {
                JsonNode data = nexus.get(SCOPE_COMMERCIAL, "/api/v1/tenants/" + tenantId + "/commercial-context");
                Entitlements entitlements = parseEntitlements(tenantId, data);
                if (entitlementCache.size() > MAX_CACHE_ENTRIES) {
                    entitlementCache.clear();
                }
                entitlementCache.put(tenantId, entitlements);
                return entitlements;
            } catch (NexusClient.UnavailableException e) {
                throw down(e);
            } catch (NexusClient.RejectedException e) {
                if (e.getStatus() == 403) {
                    LOGGER.error("OptiNexus refused the OptiRadar service account for commercial data ({}): the "
                            + "service account needs the commercial.read scope", e.getCode());
                    throw down(new NexusClient.UnavailableException(e.getCode(), 30, e));
                }
                // Unknown tenant: nothing is entitled.
                Entitlements none = new Entitlements(false, Set.of(), Set.of(),
                        now() + TimeUnit.SECONDS.toMillis(DENY_TTL_SECONDS));
                entitlementCache.put(tenantId, none);
                return none;
            }
        }
    }

    private Entitlements parseEntitlements(String tenantId, JsonNode data) throws NexusClient.UnavailableException {
        if (!tenantId.equalsIgnoreCase(data.path("tenant_id").asText())) {
            throw new NexusClient.UnavailableException("OptiNexus gave an answer for another tenant", 30, null);
        }
        boolean active = "ACTIVE".equals(data.path("tenant_status").asText());
        boolean application = false;
        for (JsonNode code : data.path("applications_enabled")) {
            if (applicationCode.equals(code.asText())) {
                application = true;
            }
        }
        Set<String> enabled = new HashSet<>();
        Set<String> disabled = new HashSet<>();
        for (JsonNode entry : data.path("effective_entitlements")) {
            if ("CAPABILITY".equals(entry.path("entitlement_type").asText())) {
                String code = entry.path("entitlement_key").asText("");
                if (entry.path("value").asBoolean(false)) {
                    enabled.add(code);
                } else {
                    disabled.add(code);
                }
            }
        }
        boolean entitled = active && application;
        long ttl = entitled ? ttlSeconds : Math.min(ttlSeconds, DENY_TTL_SECONDS);
        return new Entitlements(entitled, Set.copyOf(enabled), Set.copyOf(disabled),
                now() + TimeUnit.SECONDS.toMillis(ttl));
    }

    /**
     * Called after an OpenID sign-in and the tenant link, before the session starts: the account must now be a tenant
     * account, and OptiNexus must not report its access as ended. The grants are fetched here so the first request
     * is already decided. Anything that only means "cannot be decided now" lets the sign-in through; every request is
     * decided again.
     *
     * @throws GeneralSecurityException if the account cannot be a tenant user or OptiNexus ended its access
     */
    public void admit(User user) throws GeneralSecurityException {
        invalidate(user.getId());
        GovernedPrincipal principal = principal(user);
        if (principal.kind() != GovernedPrincipal.Kind.CENTRAL) {
            throw new GeneralSecurityException("The account cannot be used as a tenant user: " + principal.kind());
        }
        try {
            context(principal);
        } catch (GovernanceException e) {
            if (e.getStatus() == 401) {
                throw new GeneralSecurityException("OptiNexus reports the access of this user ended", e);
            }
            LOGGER.info("Grants of user {} are not available at sign-in ({})", user.getId(), e.getCode());
        }
    }

    // ---------------------------------------------------------------------------------------------------------
    // Invalidation

    /**
     * Forget what is known about a user: after a sign-in, a tenant change or an event from OptiNexus. The next request
     * asks OptiNexus again.
     */
    public void invalidate(long userId) {
        principals.remove(userId);
        String key = grantKeys.remove(userId);
        if (key != null) {
            grantCache.remove(key);
            productCache.remove(key);
        }
    }

    /**
     * The roles of one person changed at OptiNexus through this server: forget what is known about them, so the next
     * request asks again instead of using up to five minutes of old grants.
     */
    public void invalidateSubject(String tenantId, String subject) {
        if (tenantId != null && subject != null) {
            String key = tenantId.toLowerCase(Locale.ROOT) + "|" + subject.toLowerCase(Locale.ROOT);
            grantCache.remove(key);
            productCache.remove(key);
        }
    }

    /**
     * A role of the tenant changed: everyone in the tenant may hold different grants now.
     */
    public void invalidateTenant(String tenantId) {
        if (tenantId != null) {
            String prefix = tenantId.toLowerCase(Locale.ROOT) + "|";
            grantCache.keySet().removeIf(key -> key.startsWith(prefix));
            productCache.keySet().removeIf(key -> key.startsWith(prefix));
        }
    }

    public void invalidateAll() {
        principals.clear();
        grantKeys.clear();
        grantCache.clear();
        productCache.clear();
        entitlementCache.clear();
    }

    /**
     * OptiNexus said the user's access ended: end the user's sessions (rate limited, since a denied user keeps
     * calling).
     */
    public void endSessions(long userId) {
        try {
            User user = storage.getObject(User.class, new Request(
                    new Columns.All(), new Condition.Equals("id", userId)));
            if (user == null) {
                return;
            }
            long notBefore = user.getLong(OpenIdLifecycle.SESSIONS_NOT_BEFORE);
            if (notBefore > 0 && now() - notBefore < TimeUnit.SECONDS.toMillis(60)) {
                return;
            }
            lifecycle.endSessions(user);
            invalidate(userId);
        } catch (Exception e) {
            LOGGER.warn("Cannot end the sessions of user {}", userId, e);
        }
    }

}
