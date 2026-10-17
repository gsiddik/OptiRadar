package org.traccar.governance;

import com.fasterxml.jackson.databind.JsonNode;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The answer of OptiNexus {@code POST /authorization/product-context} (schema 1.0), reduced to what a product switcher
 * may show. Nothing else from the answer reaches the browser:
 *
 * <ul>
 * <li>the answer must be about this user, this tenant and this application, otherwise it is not used;</li>
 * <li>a product needs a code, a name and an absolute http(s) address without credentials, otherwise it is dropped;</li>
 * <li>the governance portal ({@code cgo}) is never listed, and the current product is decided here, not by the
 * answer;</li>
 * <li>every address carries {@code tenant_hint=<tenant id>} (the hint is the only thing added), so the target's SSO
 * start opens the same tenant without asking for credentials again.</li>
 * </ul>
 */
public final class ProductContext {

    /** Applications that are never shown in a switcher. */
    static final Set<String> HIDDEN = Set.of("cgo");

    private static final int MAX_PRODUCTS = 20;
    private static final int MAX_NAME = 80;
    private static final Pattern CODE = Pattern.compile("[a-z0-9][a-z0-9_-]{0,63}");

    private ProductContext() {
    }

    public record Tenant(String id, String code, String name) {
    }

    public record Product(String code, String name, String url, boolean current) {
    }

    /**
     * What OptiNexus decided. {@code allowed=false} means the caller's own session must end.
     */
    public record Decision(boolean allowed, String denyReason, Tenant tenant, List<Product> products, int ttlSeconds) {
    }

    /**
     * Parses and checks the answer.
     *
     * @throws IllegalArgumentException if the answer is about somebody or something else or not in schema 1.0
     */
    public static Decision parse(JsonNode data, String subject, String tenantId, String applicationCode) {
        if (!"1.0".equals(data.path("schema_version").asText())
                || !subject.equalsIgnoreCase(data.path("user_id").asText())
                || !applicationCode.equals(data.path("application_code").asText())) {
            throw new IllegalArgumentException("The answer is about another subject or application");
        }
        int ttl = Math.max(1, data.path("ttl_seconds").asInt(0));
        if (!data.path("allowed").asBoolean(false)) {
            String reason = data.hasNonNull("deny_reason") ? sanitizeReason(data.get("deny_reason").asText()) : null;
            return new Decision(false, reason, null, List.of(), ttl);
        }
        JsonNode node = data.path("tenant");
        if (!tenantId.equalsIgnoreCase(node.path("id").asText())) {
            throw new IllegalArgumentException("The answer is about another tenant");
        }
        Tenant tenant = new Tenant(tenantId.toLowerCase(Locale.ROOT), clean(node.path("code").asText(""), 64),
                clean(node.path("name").asText(""), MAX_NAME));
        Map<String, Product> products = new LinkedHashMap<>();
        for (JsonNode entry : data.path("products")) {
            Product product = product(entry, tenant.id(), applicationCode);
            if (product != null && products.size() < MAX_PRODUCTS) {
                products.putIfAbsent(product.code(), product);
            }
        }
        return new Decision(true, null, tenant, List.copyOf(products.values()), ttl);
    }

    private static Product product(JsonNode entry, String tenantId, String applicationCode) {
        String code = entry.path("code").asText("").trim().toLowerCase(Locale.ROOT);
        String name = clean(entry.path("name").asText(""), MAX_NAME);
        if (!CODE.matcher(code).matches() || HIDDEN.contains(code) || name.isEmpty()) {
            return null;
        }
        String url = withTenantHint(entry.path("launch_url").asText(""), tenantId);
        if (url == null) {
            return null;
        }
        return new Product(code, name, url, code.equals(applicationCode));
    }

    /**
     * The address with {@code tenant_hint=<tenant id>} as the only added query parameter (an existing hint is
     * replaced, the fragment is dropped), or null when it is not an absolute http(s) address without credentials.
     */
    static String withTenantHint(String launchUrl, String tenantId) {
        if (launchUrl == null || launchUrl.isBlank() || launchUrl.length() > 2048) {
            return null;
        }
        URI uri;
        try {
            uri = URI.create(launchUrl.trim());
        } catch (IllegalArgumentException e) {
            return null;
        }
        String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase(Locale.ROOT) : "";
        if (!("https".equals(scheme) || "http".equals(scheme)) || uri.getRawAuthority() == null
                || uri.getHost() == null || uri.getRawUserInfo() != null) {
            return null;
        }
        List<String> query = new ArrayList<>();
        if (uri.getRawQuery() != null) {
            for (String part : uri.getRawQuery().split("&")) {
                if (!part.isEmpty() && !part.equals("tenant_hint") && !part.startsWith("tenant_hint=")) {
                    query.add(part);
                }
            }
        }
        query.add("tenant_hint=" + tenantId.toLowerCase(Locale.ROOT));
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        return scheme + "://" + uri.getRawAuthority() + path + "?" + String.join("&", query);
    }

    private static String sanitizeReason(String reason) {
        String value = reason.trim().toLowerCase(Locale.ROOT);
        return value.matches("[a-z0-9_]{1,64}") ? value : "access_ended";
    }

    private static String clean(String value, int max) {
        String text = value.replaceAll("\\p{Cntrl}", " ").trim();
        return text.length() > max ? text.substring(0, max) : text;
    }

}
