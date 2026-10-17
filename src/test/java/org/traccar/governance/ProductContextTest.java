package org.traccar.governance;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ProductContextTest {

    private static final String TENANT = "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c01";
    private static final String SUBJECT = "5d3a7f9e-1b2c-4d5e-8f60-7a8b9c0d1e01";

    private static ProductContext.Decision parse(String json) throws Exception {
        return ProductContext.parse(new ObjectMapper().readTree(json), SUBJECT, TENANT, "optiradar");
    }

    @Test
    public void aDeniedAnswerKeepsOnlyASafeReason() throws Exception {
        ProductContext.Decision decision = parse(FakeNexus.productContext(
                SUBJECT, TENANT, "acme", "optiradar", false, "user_suspended", 300, List.of()));
        assertFalse(decision.allowed());
        assertEquals("user_suspended", decision.denyReason());
        assertTrue(decision.products().isEmpty());
        assertNull(decision.tenant());

        decision = parse(FakeNexus.productContext(
                SUBJECT, TENANT, "acme", "optiradar", false, "<script>alert(1)</script>", 300, List.of()));
        assertEquals("access_ended", decision.denyReason());
    }

    @Test
    public void aDeniedAnswerStaysDeniedEvenIfItCarriesProducts() throws Exception {
        String body = "{\"schema_version\":\"1.0\",\"user_id\":\"" + SUBJECT + "\",\"application_code\":\"optiradar\","
                + "\"allowed\":false,\"deny_reason\":\"tenant_suspended\",\"products\":[{\"code\":\"optifleet\","
                + "\"name\":\"OptiFleet\",\"launch_url\":\"https://fleet.example.test\"}],\"ttl_seconds\":300}";
        ProductContext.Decision decision = parse(body);

        assertFalse(decision.allowed());
        assertTrue(decision.products().isEmpty());
    }

    @Test
    public void aMissingAllowedFlagIsADenial() throws Exception {
        ProductContext.Decision decision = parse("{\"schema_version\":\"1.0\",\"user_id\":\"" + SUBJECT
                + "\",\"application_code\":\"optiradar\",\"products\":[]}");
        assertFalse(decision.allowed());
    }

    @Test
    public void anAnswerAboutAnotherTenantIsRefused() {
        String other = FakeNexus.productContext(SUBJECT, "0b1f6c1e-6a3a-4c5e-9d52-6f0f6a1b2c02", "other", "optiradar",
                true, null, 300, List.of());
        assertThrows(IllegalArgumentException.class, () -> parse(other));
    }

    @Test
    public void tenantHintKeepsOtherParametersAndReplacesTheHint() {
        assertEquals("https://a.example.test/?tenant_hint=" + TENANT,
                ProductContext.withTenantHint("https://a.example.test", TENANT));
        assertEquals("http://a.example.test:8080/x/y?a=1&b=%20&tenant_hint=" + TENANT,
                ProductContext.withTenantHint("http://a.example.test:8080/x/y?a=1&tenant_hint=old&b=%20#frag", TENANT));
        assertEquals("https://a.example.test/?tenant_hint=" + TENANT,
                ProductContext.withTenantHint("https://a.example.test/?tenant_hint", TENANT));
    }

    @Test
    public void tenantHintRefusesWhatIsNotAnAbsoluteWebAddress() {
        List<String> refused = Arrays.asList(
                null, "", "  ", "ftp://a.example.test", "//a.example.test", "a.example.test", "javascript:alert(1)",
                "https://u:p@a.example.test", "https://u@a.example.test", "https://", "https:/a", "not a url",
                "https://a.example.test/" + "x".repeat(2100));
        for (String value : refused) {
            assertNull(ProductContext.withTenantHint(value, TENANT), String.valueOf(value));
        }
    }

    @Test
    public void tenantHintOfUppercaseSchemeIsNormalised() {
        assertEquals("https://A.example.test/?tenant_hint=" + TENANT,
                ProductContext.withTenantHint("HTTPS://A.example.test", TENANT.toUpperCase()));
    }

}
