package dev.aib.orders;

import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

/**
 * Decides whether the caller may perform one action on one order. Scope checks have
 * already happened in {@link SecurityConfig}.
 *
 * <p>For a broker access token: the request must match the token's authorization_details,
 * and before any write the broker is asked whether the token is still active (it may have
 * been revoked, or its agent disabled). Reads rely on the token's short lifetime instead.
 *
 * <p>For the static demo key (no broker): everything is allowed. That is the point of the
 * contrast.
 */
@Component
class AccessCheck {

    private static final Logger log = LoggerFactory.getLogger(AccessCheck.class);

    /** Who did it: the human the token is for, and the agent acting for them. */
    record PerformedBy(String user, String agent) {}

    private final OpaqueTokenIntrospector introspector;

    AccessCheck(OpaqueTokenIntrospector introspector) {
        this.introspector = introspector;
    }

    void read(Authentication caller, String orderId) {
        if (tokenOf(caller) instanceof Jwt jwt) {
            TokenGrant.of(jwt).requireOrder("read", orderId);
        }
    }

    void list(Authentication caller, String customerId) {
        if (tokenOf(caller) instanceof Jwt jwt) {
            TokenGrant.of(jwt).requireCustomerList(customerId);
        }
    }

    void refund(Authentication caller, String orderId, long amountCents) {
        if (tokenOf(caller) instanceof Jwt jwt) {
            TokenGrant.of(jwt).requireRefund(orderId, amountCents);
            requireActive(jwt);
        }
    }

    void write(Authentication caller, String type, String orderId) {
        if (tokenOf(caller) instanceof Jwt jwt) {
            TokenGrant.of(jwt).requireOrder(type, orderId);
            requireActive(jwt);
        }
    }

    PerformedBy performedBy(Authentication caller) {
        if (tokenOf(caller) instanceof Jwt jwt) {
            Map<String, Object> act = jwt.getClaimAsMap("act");
            return new PerformedBy(jwt.getSubject(), act == null ? null : (String) act.get("sub"));
        }
        return new PerformedBy(null, DemoKeyFilter.CALLER_NAME);
    }

    private static Jwt tokenOf(Authentication caller) {
        return caller instanceof JwtAuthenticationToken token ? token.getToken() : null;
    }

    /** Introspection (RFC 7662). Fails closed: if the broker cannot be reached, the write is refused. */
    private void requireActive(Jwt jwt) {
        try {
            introspector.introspect(jwt.getTokenValue());
        } catch (BadOpaqueTokenException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token has been revoked");
        } catch (OAuth2IntrospectionException e) {
            log.error("Introspection failed for token {}", jwt.getId(), e);
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Cannot confirm the token is still valid");
        }
    }
}
