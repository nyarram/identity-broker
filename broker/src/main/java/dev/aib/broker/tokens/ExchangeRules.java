package dev.aib.broker.tokens;

import com.nimbusds.jose.util.JSONArrayUtils;
import dev.aib.broker.config.BrokerProperties;
import dev.aib.broker.delegations.Delegation;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.stereotype.Component;

/**
 * Decides what a token exchange may grant. Spring Authorization Server checks the client
 * and the subject token; these rules bind the result to the delegation. Policy evaluation
 * (Cedar) is added in M2.
 */
@Component
public class ExchangeRules {

    static final int MAX_AUTHORIZATION_DETAILS_LENGTH = 4096;

    public record Request(
            String agentId,
            Set<String> scopes,
            Set<String> resources,
            Set<String> audiences,
            String authorizationDetails) {}

    public record Grant(
            String audience,
            Set<String> scopes,
            List<Map<String, Object>> authorizationDetails,
            Instant expiresAt) {}

    /** A refused exchange, carrying the OAuth error code to return. */
    public static class Denied extends RuntimeException {
        private final String code;

        Denied(String code, String description) {
            super(description);
            this.code = code;
        }

        public String code() {
            return code;
        }
    }

    private final BrokerProperties properties;

    ExchangeRules(BrokerProperties properties) {
        this.properties = properties;
    }

    /**
     * @param agentAudiences the resources the agent was registered for
     * @param defaultExpiry when the token would expire under the normal lifetime
     */
    public Grant evaluate(
            Request request, Delegation delegation, List<String> agentAudiences, Instant now, Instant defaultExpiry) {
        if (!delegation.agentId().equals(request.agentId())) {
            throw new Denied("invalid_grant", "The delegation was issued to a different agent");
        }
        if (!delegation.isActive(now)) {
            throw new Denied("invalid_grant", "The delegation has expired or been revoked");
        }

        if (!request.audiences().isEmpty()) {
            throw new Denied("invalid_target", "Use the resource parameter (RFC 8707), not audience");
        }
        if (request.resources().size() != 1) {
            throw new Denied("invalid_target", "Exactly one resource is required");
        }
        String resource = request.resources().iterator().next();
        var known = properties.resource(resource);
        if (known.isEmpty() || !agentAudiences.contains(resource)) {
            throw new Denied("invalid_target", "Agent may not request tokens for " + resource);
        }

        Set<String> scopes = new TreeSet<>(request.scopes());
        if (scopes.isEmpty()) {
            throw new Denied("invalid_scope", "scope is required");
        }
        if (!delegation.scopes().containsAll(scopes)) {
            throw new Denied("invalid_scope", "Requested scope exceeds the delegation");
        }
        if (!known.get().scopes().containsAll(scopes)) {
            throw new Denied("invalid_scope", "Requested scope is not valid for " + resource);
        }

        // A token never outlives the delegation it came from
        Instant expiresAt = defaultExpiry.isBefore(delegation.expiresAt()) ? defaultExpiry : delegation.expiresAt();

        return new Grant(resource, scopes, parseAuthorizationDetails(request.authorizationDetails()), expiresAt);
    }

    /** Structural checks only for RFC 9396 authorization_details; M2 checks values against policy. */
    static List<Map<String, Object>> parseAuthorizationDetails(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        if (json.length() > MAX_AUTHORIZATION_DETAILS_LENGTH) {
            throw new Denied("invalid_authorization_details", "authorization_details is too large");
        }
        List<Object> entries;
        try {
            entries = JSONArrayUtils.parse(json);
        } catch (ParseException e) {
            throw new Denied("invalid_authorization_details", "authorization_details must be a JSON array");
        }
        List<Map<String, Object>> details = new ArrayList<>();
        for (Object entry : entries) {
            if (!(entry instanceof Map<?, ?> map) || !(map.get("type") instanceof String type) || type.isBlank()) {
                throw new Denied("invalid_authorization_details", "Each authorization_details entry needs a type");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> typed = (Map<String, Object>) map;
            details.add(typed);
        }
        return details;
    }
}
