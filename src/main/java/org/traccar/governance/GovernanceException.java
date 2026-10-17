package org.traccar.governance;

/**
 * An access decision that is not "allowed". The {@code code} is stable and English (the web app translates it); the
 * message is for logs and support only.
 */
public class GovernanceException extends RuntimeException {

    public static final String ACCESS_REVOKED = "governance_access_revoked";
    public static final String PERMISSION_DENIED = "governance_permission_denied";
    public static final String NOT_ENTITLED = "governance_not_entitled";
    public static final String OPERATOR_ONLY = "governance_operator_only";
    public static final String IDENTITY_REQUIRED = "governance_identity_required";
    public static final String TENANT_UNRESOLVED = "governance_tenant_unresolved";
    public static final String UNAVAILABLE = "governance_unavailable";
    public static final String ROUTE_UNMAPPED = "governance_route_unmapped";
    public static final String INVALID_PLACEMENT = "governance_invalid_placement";
    public static final String RESERVED_ATTRIBUTE = "governance_reserved_attribute";

    private final int status;
    private final String code;
    private final String permission;
    private final int retryAfterSeconds;
    private final boolean endSessions;

    public GovernanceException(int status, String code, String message, String permission) {
        this(status, code, message, permission, 0, false);
    }

    public GovernanceException(
            int status, String code, String message, String permission, int retryAfterSeconds, boolean endSessions) {
        super(message);
        this.status = status;
        this.code = code;
        this.permission = permission;
        this.retryAfterSeconds = retryAfterSeconds;
        this.endSessions = endSessions;
    }

    public int getStatus() {
        return status;
    }

    public String getCode() {
        return code;
    }

    /**
     * The permission that was missing, when the decision was about one.
     */
    public String getPermission() {
        return permission;
    }

    public int getRetryAfterSeconds() {
        return retryAfterSeconds;
    }

    /**
     * True when OptiNexus says the user, the tenant or the application is no longer active: the user's web sessions
     * must end.
     */
    public boolean endsSessions() {
        return endSessions;
    }

}
