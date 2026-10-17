package org.traccar.governance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.traccar.model.User;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Condition;
import org.traccar.storage.query.Request;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Audit A29/R06: the product switcher's data comes only from OptiNexus product-context, is cached for at most five
 * minutes, fails closed, never lists the governance portal and ends the session when the access ended.
 */
public class ProductSwitcherTest extends GovernanceTestBase {

    private static final String PATH = "/api/v1/authorization/product-context";

    private volatile String productsBody;
    private volatile FakeNexus.Reply productsReply;

    private static Map<String, Object> product(String code, String name, String url, boolean current) {
        Map<String, Object> product = new LinkedHashMap<>();
        product.put("code", code);
        product.put("name", name);
        product.put("launch_url", url);
        product.put("current", current);
        return product;
    }

    private static List<Map<String, Object>> defaultProducts() {
        return List.of(
                product("optiradar", "OptiRadar", "https://radar.example.test", true),
                product("optifleet", "OptiFleet", "https://fleet.example.test", false),
                product("optiaccounting", "OptiEntry", "https://entry.example.test/app", false));
    }

    private String answer(String subject, String tenant, int ttl, List<Map<String, Object>> products) {
        return FakeNexus.productContext(subject, tenant, "acme", APP, true, null, ttl, products);
    }

    @BeforeEach
    public void routeProducts() {
        productsBody = answer(SUBJECT_1, TENANT_A, 300, defaultProducts());
        productsReply = null;
        nexus.route("POST", PATH, GovernanceService.SCOPE_AUTHORIZATION,
                call -> productsReply != null ? productsReply : FakeNexus.Reply.ok(productsBody));
    }

    private GovernedPrincipal alice(GovernanceService service) throws Exception {
        return service.principal(addTenantUser("alice", SUBJECT_1, groupA).getId());
    }

    @Test
    public void listsWhatOptiNexusAllowsEachWithTheTenantHint() throws Exception {
        GovernanceService service = service();

        GovernanceService.Products products = service.products(alice(service), false);

        assertEquals(TENANT_A, products.tenant().id());
        assertEquals(3, products.products().size());
        ProductContext.Product fleet = products.products().get(1);
        assertEquals("optifleet", fleet.code());
        assertEquals("https://fleet.example.test/?tenant_hint=" + TENANT_A, fleet.url());
        assertEquals("https://entry.example.test/app?tenant_hint=" + TENANT_A, products.products().get(2).url());
    }

    @Test
    public void theQuestionIsAboutThePrincipalNeverAboutAnythingElseAndUsesTheAuthorizationScope() throws Exception {
        GovernanceService service = service();
        service.products(alice(service), false);

        FakeNexus.Call call = nexus.calls(PATH).get(0);

        assertEquals(GovernanceService.SCOPE_AUTHORIZATION, call.scope());
        JsonNode body = new ObjectMapper().readTree(call.body());
        assertEquals(2, body.size(), "nothing but the two ids is sent");
        assertEquals(SUBJECT_1, body.get("user_id").asText());
        assertEquals(TENANT_A, body.get("tenant_id").asText());
    }

    @Test
    public void theGovernancePortalIsNeverListedEvenIfOptiNexusSendsIt() throws Exception {
        List<Map<String, Object>> list = new ArrayList<>(defaultProducts());
        list.add(product("cgo", "Governance", "https://portal.example.test", false));
        list.add(product("CGO", "Governance again", "https://portal.example.test", false));
        productsBody = answer(SUBJECT_1, TENANT_A, 300, list);
        GovernanceService service = service();

        List<String> codes = service.products(alice(service), false).products().stream()
                .map(ProductContext.Product::code).toList();

        assertEquals(List.of("optiradar", "optifleet", "optiaccounting"), codes);
    }

    @Test
    public void onlyTheServerDecidesWhichProductIsTheCurrentOne() throws Exception {
        productsBody = answer(SUBJECT_1, TENANT_A, 300, List.of(
                product("optiradar", "OptiRadar", "https://radar.example.test", false),
                product("optifleet", "OptiFleet", "https://fleet.example.test", true)));
        GovernanceService service = service();

        List<ProductContext.Product> products = service.products(alice(service), false).products();

        assertTrue(products.get(0).current());
        assertFalse(products.get(1).current());
    }

    @Test
    public void addressesThatCouldBeAnythingOtherThanAWebPageAreDropped() throws Exception {
        productsBody = answer(SUBJECT_1, TENANT_A, 300, List.of(
                product("a", "Script", "javascript:alert(1)", false),
                product("b", "Data", "data:text/html;base64,AAAA", false),
                product("c", "Relative", "/just/a/path", false),
                product("d", "Credentials", "https://user:secret@evil.example.test/", false),
                product("e", "File", "file:///etc/passwd", false),
                product("f", "No host", "https:///path", false),
                product("g", "Custom scheme", "org.traccar.manager://openid", false),
                product("h", "Blank", " ", false),
                product("optifleet", "OptiFleet", "https://fleet.example.test", false)));
        GovernanceService service = service();

        List<String> codes = service.products(alice(service), false).products().stream()
                .map(ProductContext.Product::code).toList();

        assertEquals(List.of("optifleet"), codes);
    }

    @Test
    public void theHintIsTheOnlyThingAddedAndAnOldHintOrFragmentIsReplaced() throws Exception {
        productsBody = answer(SUBJECT_1, TENANT_A, 300, List.of(
                product("optifleet", "OptiFleet",
                        "https://fleet.example.test/start?lang=id&tenant_hint=someone-else#token=abc", false)));
        GovernanceService service = service();

        String url = service.products(alice(service), false).products().get(0).url();

        assertEquals("https://fleet.example.test/start?lang=id&tenant_hint=" + TENANT_A, url);
        assertFalse(url.contains("someone-else"));
        assertFalse(url.contains("token"));
    }

    @Test
    public void namesAreCleanedDuplicatesDroppedAndTheListIsBounded() throws Exception {
        List<Map<String, Object>> list = new ArrayList<>();
        list.add(product("optifleet", "Opti\u0007Fleet\n" + "x".repeat(200), "https://fleet.example.test", false));
        list.add(product("optifleet", "Duplicate", "https://other.example.test", false));
        list.add(product("bad code!", "Bad", "https://x.example.test", false));
        list.add(product("nameless", "  ", "https://x.example.test", false));
        for (int i = 0; i < 40; i++) {
            list.add(product("p" + i, "Product " + i, "https://p" + i + ".example.test", false));
        }
        productsBody = answer(SUBJECT_1, TENANT_A, 300, list);
        GovernanceService service = service();

        List<ProductContext.Product> products = service.products(alice(service), false).products();

        assertEquals(20, products.size());
        assertEquals("optifleet", products.get(0).code());
        assertTrue(products.get(0).name().length() <= 80);
        assertFalse(products.get(0).name().chars().anyMatch(Character::isISOControl));
        assertEquals("https://fleet.example.test/?tenant_hint=" + TENANT_A, products.get(0).url());
    }

    // ---------------------------------------------------------------------------------------------------------
    // Cache and revalidation

    @Test
    public void theAnswerIsCachedForAtMostFiveMinutes() throws Exception {
        GovernanceService service = service();
        GovernedPrincipal alice = alice(service);

        service.products(alice, false);
        service.products(alice, false);
        assertEquals(1, nexus.calls(PATH).size(), "the second render uses the cache");

        clock.addAndGet(TimeUnit.SECONDS.toMillis(299));
        service.products(alice, false);
        assertEquals(1, nexus.calls(PATH).size());

        clock.addAndGet(TimeUnit.SECONDS.toMillis(2));
        service.products(alice, false);
        assertEquals(2, nexus.calls(PATH).size(), "after 300 seconds OptiNexus is asked again");
    }

    @Test
    public void aLongerTtlFromOptiNexusIsCappedAndAShorterOneIsHonoured() throws Exception {
        productsBody = answer(SUBJECT_1, TENANT_A, 3600, defaultProducts());
        GovernanceService service = service();
        GovernedPrincipal alice = alice(service);

        GovernanceService.Products capped = service.products(alice, false);
        assertEquals(300, capped.ttlSeconds());

        service.invalidateAll();
        productsBody = answer(SUBJECT_1, TENANT_A, 20, defaultProducts());
        GovernanceService.Products shorter = service.products(alice, false);
        assertEquals(20, shorter.ttlSeconds());
        clock.addAndGet(TimeUnit.SECONDS.toMillis(21));
        int before = nexus.calls(PATH).size();
        service.products(alice, false);
        assertEquals(before + 1, nexus.calls(PATH).size());
    }

    @Test
    public void freshAsksAgainButAtMostOnceEveryFiveSeconds() throws Exception {
        GovernanceService service = service();
        GovernedPrincipal alice = alice(service);

        service.products(alice, true);
        service.products(alice, true);
        service.products(alice, true);
        assertEquals(1, nexus.calls(PATH).size(), "a busy switcher does not flood OptiNexus");

        clock.addAndGet(TimeUnit.SECONDS.toMillis(6));
        service.products(alice, true);
        assertEquals(2, nexus.calls(PATH).size(), "a switcher that opens later revalidates");
    }

    @Test
    public void aFreshQuestionSeesAProductThatWasRemoved() throws Exception {
        GovernanceService service = service();
        GovernedPrincipal alice = alice(service);
        assertEquals(3, service.products(alice, false).products().size());

        productsBody = answer(SUBJECT_1, TENANT_A, 300, List.of(defaultProducts().get(0)));
        clock.addAndGet(TimeUnit.SECONDS.toMillis(6));

        assertEquals(1, service.products(alice, true).products().size());
    }

    @Test
    public void concurrentRendersShareOneQuestion() throws Exception {
        nexus.setDelayMillis(150);
        GovernanceService service = service();
        GovernedPrincipal alice = alice(service);
        service.requireSignedIn(alice);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return service.products(alice, true);
            }));
        }
        start.countDown();
        for (Future<?> future : futures) {
            future.get(10, TimeUnit.SECONDS);
        }
        pool.shutdownNow();

        assertEquals(1, nexus.calls(PATH).size());
    }

    @Test
    public void droppingAUsersGrantsAlsoDropsTheirProducts() throws Exception {
        GovernanceService service = service();
        User user = addTenantUser("alice", SUBJECT_1, groupA);
        GovernedPrincipal alice = service.principal(user.getId());
        service.products(alice, false);

        service.invalidate(user.getId());
        service.products(service.principal(user.getId()), false);

        assertEquals(2, nexus.calls(PATH).size());
    }

    @Test
    public void tenantAndSubjectInvalidationDropProductsToo() throws Exception {
        GovernanceService service = service();
        GovernedPrincipal alice = alice(service);
        service.products(alice, false);

        service.invalidateSubject(TENANT_A, SUBJECT_1.toUpperCase());
        service.products(alice, false);
        assertEquals(2, nexus.calls(PATH).size());

        service.invalidateTenant(TENANT_A);
        service.products(alice, false);
        assertEquals(3, nexus.calls(PATH).size());

        service.invalidateAll();
        service.products(alice, false);
        assertEquals(4, nexus.calls(PATH).size());
    }

    // ---------------------------------------------------------------------------------------------------------
    // Access ended

    @Test
    public void whenOptiNexusSaysAccessEndedTheSessionEndsAndTheGrantsAreCleared() throws Exception {
        GovernanceService service = service();
        User user = addTenantUser("alice", SUBJECT_1, groupA);
        GovernedPrincipal alice = service.principal(user.getId());
        service.require(alice, List.of(Catalog.LIVE_VIEW));
        service.products(alice, false);
        assertEquals(1, nexus.calls("/api/v1/authorization/effective-permissions").size());
        productsBody = FakeNexus.productContext(SUBJECT_1, TENANT_A, "acme", APP, false,
                "application_access_revoked", 300, List.of());
        clock.addAndGet(TimeUnit.SECONDS.toMillis(6));

        GovernanceException e = refused(() -> service.products(alice, true));

        assertEquals(401, e.getStatus());
        assertEquals(GovernanceException.ACCESS_REVOKED, e.getCode());
        assertTrue(e.endsSessions());
        long notBefore = storage.getObject(User.class, new Request(new Columns.All(),
                new Condition.Equals("id", user.getId()))).getLong("optinexusSessionsNotBefore");
        assertTrue(notBefore > 0, "the user's sessions are ended");

        // cached grants are gone: the next decision asks OptiNexus again instead of trusting the old ones
        service.require(service.principal(user.getId()), List.of(Catalog.LIVE_VIEW));
        assertEquals(2, nexus.calls("/api/v1/authorization/effective-permissions").size());
        // and the cached product list is gone too
        productsBody = answer(SUBJECT_1, TENANT_A, 300, defaultProducts());
        service.products(service.principal(user.getId()), false);
        assertEquals(3, nexus.calls(PATH).size());
    }

    @Test
    public void everyDenyReasonOfTheContractEndsTheSession() throws Exception {
        GovernanceService service = service();
        User user = addTenantUser("alice", SUBJECT_1, groupA);
        for (String reason : List.of("user_suspended", "tenant_membership_removed", "application_access_revoked",
                "application_not_assigned", "tenant_suspended", "user_not_found", "tenant_not_found")) {
            service.invalidateAll();
            clock.addAndGet(TimeUnit.SECONDS.toMillis(120));
            productsBody = FakeNexus.productContext(SUBJECT_1, TENANT_A, "acme", APP, false, reason, 300, List.of());
            GovernedPrincipal alice = service.principal(user.getId());

            GovernanceException e = refused(() -> service.products(alice, true));

            assertEquals(GovernanceException.ACCESS_REVOKED, e.getCode(), reason);
            assertTrue(e.endsSessions(), reason);
        }
    }

    // ---------------------------------------------------------------------------------------------------------
    // Fail closed

    @Test
    public void whenOptiNexusIsDownNothingIsListedAndNothingIsCached() throws Exception {
        GovernanceService service = service();
        GovernedPrincipal alice = alice(service);
        service.requireSignedIn(alice);
        productsReply = FakeNexus.Reply.error(503, "UNAVAILABLE", "down").withHeader("Retry-After", "7");

        GovernanceException e = refused(() -> service.products(alice, false));

        assertEquals(503, e.getStatus());
        assertEquals(GovernanceException.UNAVAILABLE, e.getCode());
        assertFalse(e.endsSessions(), "an outage never ends a session");

        productsReply = null;
        clock.addAndGet(TimeUnit.SECONDS.toMillis(8));
        assertEquals(3, service.products(alice, false).products().size(), "the next render works once it is back");
    }

    @Test
    public void anAnswerAboutSomebodyOrSomethingElseIsNotUsed() throws Exception {
        GovernanceService service = service();
        GovernedPrincipal alice = alice(service);
        service.requireSignedIn(alice);
        List<String> wrong = List.of(
                answer(SUBJECT_2, TENANT_A, 300, defaultProducts()),
                answer(SUBJECT_1, TENANT_B, 300, defaultProducts()),
                FakeNexus.productContext(SUBJECT_1, TENANT_A, "acme", "optifleet", true, null, 300, defaultProducts()),
                answer(SUBJECT_1, TENANT_A, 300, defaultProducts()).replace("\"1.0\"", "\"2.0\""),
                "{}");
        for (String body : wrong) {
            service.invalidateAll();
            productsBody = body;
            GovernanceException e = refused(() -> service.products(alice, true));
            assertEquals(503, e.getStatus(), body);
            assertFalse(e.endsSessions(), body);
        }
    }

    @Test
    public void aRefusalOfTheServiceAccountListsNothingWithoutBlockingAccessChecks() throws Exception {
        GovernanceService service = service();
        GovernedPrincipal alice = alice(service);
        productsReply = FakeNexus.Reply.error(403, "INSUFFICIENT_SCOPE", "no");

        GovernanceException e = refused(() -> service.products(alice, false));

        assertEquals(503, e.getStatus());
        // the switcher is a convenience: normal access decisions keep working
        service.require(alice, List.of(Catalog.LIVE_VIEW));
    }

    @Test
    public void aMalformedAnswerIsNotAGrant() throws Exception {
        GovernanceService service = service();
        GovernedPrincipal alice = alice(service);
        productsReply = FakeNexus.Reply.raw(200, "<html>proxy</html>");

        assertEquals(503, refused(() -> service.products(alice, false)).getStatus());
    }

    // ---------------------------------------------------------------------------------------------------------
    // Who may ask

    @Test
    public void operatorsAndAccountsWithoutGrantsGetNothing() throws Exception {
        GovernanceService service = service();
        User admin = addUser("admin", true, false);
        User local = addUser("local", false, false);

        GovernanceService.Products operator = service.products(service.principal(admin.getId()), true);
        assertTrue(operator.products().isEmpty());
        assertNull(operator.tenant());
        assertEquals(403, refused(() -> service.products(service.principal(local.getId()), true)).getStatus());
        assertTrue(nexus.calls(PATH).isEmpty(), "OptiNexus is not asked for somebody who is not a tenant user");
    }

    @Test
    public void theQuestionIsNotAskedForAUserOptiNexusAlreadyDenied() throws Exception {
        permissionsBody = grants(SUBJECT_1, TENANT_A, false, "USER_NOT_ACTIVE", 300);
        GovernanceService service = service();
        GovernedPrincipal alice = alice(service);

        GovernanceException e = refused(() -> service.products(alice, true));

        assertEquals(GovernanceException.ACCESS_REVOKED, e.getCode());
        assertTrue(nexus.calls(PATH).isEmpty());
    }

    @Test
    public void tenantsDoNotShareProductLists() throws Exception {
        GovernanceService service = service();
        GovernedPrincipal alice = alice(service);
        service.products(alice, false);
        User bob = addTenantUser("bob", SUBJECT_2, groupB);
        permissionsBody = grants(SUBJECT_2, TENANT_B, true, null, 300, Catalog.LIVE_VIEW);
        productsBody = answer(SUBJECT_2, TENANT_B, 300, List.of(
                product("optiradar", "OptiRadar", "https://radar.example.test", true)));

        GovernanceService.Products other = service.products(service.principal(bob.getId()), false);

        assertEquals(TENANT_B, other.tenant().id());
        assertEquals(1, other.products().size());
        assertEquals("https://radar.example.test/?tenant_hint=" + TENANT_B, other.products().get(0).url());
        assertEquals(3, service.products(alice, false).products().size(), "alice still sees her own list");
        assertEquals(2, nexus.calls(PATH).size());
    }

}
