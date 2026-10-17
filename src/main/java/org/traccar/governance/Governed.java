package org.traccar.governance;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Says what OptiNexus must have granted for a REST route, read by {@link GovernanceRequestFilter} while governance is
 * enabled. Every route of a resource class that is not {@code @PermitAll} needs an answer here; a route without one is
 * refused for tenant users (and {@code GovernanceCoverageTest} fails the build).
 *
 * <p>On a method the annotation decides that route. On a class it is the default: {@link #read()} for GET and HEAD,
 * {@link #write()} for everything else, or {@link #access()} when it is not a permission.</p>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface Governed {

    enum Access {
        /** The permissions named by value, read or write must be granted and entitled. */
        GRANT,
        /** Any signed-in tenant user whose access OptiNexus has not ended; no particular permission. */
        SELF,
        /** Local administrators only (installation, server-wide data and break-glass). Tenant users never. */
        OPERATOR,
        /** The permissions depend on the request; {@link GovernanceRequestFilter} resolves the named rule. */
        DYNAMIC
    }

    Access access() default Access.GRANT;

    /**
     * The permission that is required on this route, whatever the HTTP method.
     */
    String value() default "";

    /**
     * Class level: the permission for GET and HEAD.
     */
    String read() default "";

    /**
     * Class level: the permission for POST, PUT, DELETE and other methods.
     */
    String write() default "";

    /**
     * With {@link Access#DYNAMIC}: the rule that names the permissions, see {@link GovernanceRequestFilter}.
     */
    String rule() default "";

    /**
     * With {@link Access#SELF}: the path parameter {@code id}, when present, must be the caller's own account.
     */
    boolean selfOnly() default false;

    /**
     * A local read-only integration account (governance.integrationUsers) may call this GET route.
     */
    boolean integration() default false;

}
