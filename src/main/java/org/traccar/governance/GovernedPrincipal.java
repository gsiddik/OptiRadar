package org.traccar.governance;

/**
 * Who a request acts as, for access decisions while governance is enabled.
 *
 * <ul>
 * <li>{@code CENTRAL}: an account tied to an OptiNexus identity and to exactly one tenant. Everything it may do comes
 * from OptiNexus (permissions and entitlements); native flags and device/group links can only restrict.</li>
 * <li>{@code OPERATOR}: a local native administrator (and the server's service account token). Not a tenant user: it
 * is the break-glass and installation role, exempt from tenant grants, never created from OpenID.</li>
 * <li>{@code INTEGRATION}: a local read-only account named in {@code governance.integrationUsers}, for machine
 * readers such as the OptiNexus telematics connector. Reads devices, groups and latest positions only.</li>
 * <li>{@code DENIED}: any other account (local password users, accounts without a tenant, accounts of several
 * tenants). Governance refuses them with {@code code}.</li>
 * </ul>
 */
public record GovernedPrincipal(Kind kind, long userId, String subject, String tenantId, String code) {

    public enum Kind { CENTRAL, OPERATOR, INTEGRATION, DENIED }

    public static GovernedPrincipal operator(long userId) {
        return new GovernedPrincipal(Kind.OPERATOR, userId, null, null, null);
    }

    public static GovernedPrincipal integration(long userId) {
        return new GovernedPrincipal(Kind.INTEGRATION, userId, null, null, null);
    }

    public static GovernedPrincipal central(long userId, String subject, String tenantId) {
        return new GovernedPrincipal(Kind.CENTRAL, userId, subject, tenantId, null);
    }

    public static GovernedPrincipal denied(long userId, String code) {
        return new GovernedPrincipal(Kind.DENIED, userId, null, null, code);
    }

}
