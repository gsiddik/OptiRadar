package org.traccar.governance;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * A refusal or failure of an access-management call (users and custom roles of a tenant, done through the OptiNexus
 * delegation API). {@code code} is stable and in OptiRadar's vocabulary ({@code delegation_*}); {@code nexusCode} is
 * the code OptiNexus gave, when it answered.
 */
public class DelegationException extends RuntimeException {

    public static final String DISABLED = "delegation_disabled";
    public static final String ACTOR_REQUIRED = "delegation_actor_required";
    public static final String INVALID_REQUEST = "delegation_invalid_request";
    public static final String UNAVAILABLE = "delegation_unavailable";
    public static final String MISCONFIGURED = "delegation_misconfigured";
    public static final String UNEXPECTED = "delegation_unexpected";

    private final int status;
    private final String code;
    private final String nexusCode;
    private final transient JsonNode details;
    private final int retryAfterSeconds;

    public DelegationException(int status, String code, String message) {
        this(status, code, null, message, null, 0);
    }

    public DelegationException(
            int status, String code, String nexusCode, String message, JsonNode details, int retryAfterSeconds) {
        super(message);
        this.status = status;
        this.code = code;
        this.nexusCode = nexusCode;
        this.details = details;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public int getStatus() {
        return status;
    }

    public String getCode() {
        return code;
    }

    public String getNexusCode() {
        return nexusCode;
    }

    public JsonNode getDetails() {
        return details;
    }

    public int getRetryAfterSeconds() {
        return retryAfterSeconds;
    }

}
