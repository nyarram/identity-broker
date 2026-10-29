package dev.aib.broker.tokens;

import com.nimbusds.jose.util.JSONArrayUtils;
import dev.aib.broker.approvals.Approval;
import dev.aib.broker.approvals.ApprovalService;
import dev.aib.broker.config.BrokerProperties;
import dev.aib.broker.delegations.Delegation;
import dev.aib.broker.policy.ActionRequest;
import dev.aib.broker.policy.ActionRequest.Action;
import dev.aib.broker.policy.PolicyEngine;
import dev.aib.broker.policy.PolicyEngine.Decision;
import dev.aib.broker.policy.PolicyEngine.Outcome;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Decides what a token exchange may grant. Spring Authorization Server checks the client
 * and the subject token; these rules bind the result to the delegation, the policy and,
 * where policy requires it, a human's approval. Each token is for exactly one action,
 * described by one authorization_details entry.
 */
@Component
public class ExchangeRules {

    static final int MAX_AUTHORIZATION_DETAILS_LENGTH = 4096;

    public record Request(
            String agentId,
            Set<String> scopes,
            Set<String> resources,
            Set<String> audiences,
            String authorizationDetails,
            String approvalId) {}

    public record Grant(
            String audience,
            Set<String> scopes,
            ActionRequest action,
            Instant expiresAt,
            String policyReason) {

        public List<Map<String, Object>> authorizationDetails() {
            return List.of(action.toAuthorizationDetail());
        }
    }

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

    /** Not refused yet: a human must decide. The agent polls the approval, then retries with its id. */
    public static class ApprovalPending extends Denied {
        private final Approval approval;

        ApprovalPending(Approval approval, String description) {
            super("authorization_pending", description);
            this.approval = approval;
        }

        public Approval approval() {
            return approval;
        }
    }

    private final BrokerProperties properties;
    private final PolicyEngine policy;
    private final ApprovalService approvals;

    ExchangeRules(BrokerProperties properties, PolicyEngine policy, ApprovalService approvals) {
        this.properties = properties;
        this.policy = policy;
        this.approvals = approvals;
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

        if (request.scopes().isEmpty()) {
            throw new Denied("invalid_scope", "scope is required");
        }
        ActionRequest action = parseAction(request.authorizationDetails());
        String scope = action.action().scope();
        if (!request.scopes().equals(Set.of(scope))) {
            throw new Denied("invalid_scope", "A token for " + action.action().type() + " must request exactly " + scope);
        }
        if (!delegation.scopes().contains(scope)) {
            throw new Denied("invalid_scope", "Requested scope exceeds the delegation");
        }
        if (!known.get().scopes().contains(scope)) {
            throw new Denied("invalid_scope", "Requested scope is not valid for " + resource);
        }

        String reason = request.approvalId() == null
                ? decide(request.agentId(), delegation, resource, action)
                : redeemApproval(request, delegation, resource, action, now);

        // A token never outlives the delegation it came from
        Instant expiresAt = defaultExpiry.isBefore(delegation.expiresAt()) ? defaultExpiry : delegation.expiresAt();

        return new Grant(resource, Set.of(scope), action, expiresAt, reason);
    }

    /** First attempt: policy permits, denies, or sends the request to a human. */
    private String decide(String agentId, Delegation delegation, String resource, ActionRequest action) {
        Decision decision = policy.evaluate(agentId, action, delegation.taskScope());
        return switch (decision.outcome()) {
            case PERMIT -> decision.reason();
            case DENY -> throw new Denied("access_denied", decision.reason());
            case APPROVAL_REQUIRED -> {
                Approval approval = approvals.requestOrReuse(agentId, delegation, resource, action, decision.reason());
                throw new ApprovalPending(approval, decision.reason());
            }
        };
    }

    /**
     * Retry with an approval id. The approval must be for this exact request, approved,
     * unexpired and unused, and policy must still permit the request with approval.
     */
    private String redeemApproval(
            Request request, Delegation delegation, String resource, ActionRequest action, Instant now) {
        Approval approval = approvals.find(request.approvalId())
                .orElseThrow(() -> new Denied("invalid_grant", "Unknown approval_id"));
        String hash = ApprovalService.requestHash(request.agentId(), delegation.id(), resource, action);
        if (!approval.requestHash().equals(hash)) {
            throw new Denied("invalid_grant", "The approval was granted for a different request");
        }
        switch (approval.statusAt(now)) {
            case PENDING -> throw new ApprovalPending(approval, "Still waiting for a human to decide");
            case DENIED -> throw new Denied("access_denied", "A human denied this request");
            case EXPIRED -> throw new Denied("access_denied", "The approval expired before it was used");
            case USED -> throw new Denied("invalid_grant", "The approval has already been used");
            case APPROVED -> {}
        }
        Decision decision = policy.evaluateApproved(request.agentId(), action, delegation.taskScope());
        if (decision.outcome() != Outcome.PERMIT) {
            throw new Denied("access_denied", decision.reason());
        }
        if (!approvals.consume(approval.id())) {
            throw new Denied("invalid_grant", "The approval has already been used");
        }
        return decision.reason() + " (" + approval.id() + ", approved by " + approval.decidedBy() + ")";
    }

    /** Parses the single RFC 9396 authorization_details entry; unknown fields are rejected. */
    static ActionRequest parseAction(String json) {
        if (json == null || json.isBlank()) {
            throw invalidDetails("authorization_details is required and must describe the one action this token is for");
        }
        if (json.length() > MAX_AUTHORIZATION_DETAILS_LENGTH) {
            throw invalidDetails("authorization_details is too large");
        }
        List<Object> entries;
        try {
            entries = JSONArrayUtils.parse(json);
        } catch (ParseException e) {
            throw invalidDetails("authorization_details must be a JSON array");
        }
        if (entries.size() != 1 || !(entries.getFirst() instanceof Map<?, ?> entry)) {
            throw invalidDetails("authorization_details must contain exactly one object");
        }
        if (!(entry.get("type") instanceof String type)) {
            throw invalidDetails("authorization_details entry needs a type");
        }
        Action action = Action.fromType(type).orElseThrow(() -> invalidDetails("Unknown authorization_details type: " + type));

        return switch (action) {
            case LIST -> {
                allowOnly(entry, Set.of("type", "customer_id"));
                yield new ActionRequest(action, null, requireString(entry, "customer_id"), 0);
            }
            case REFUND -> {
                allowOnly(entry, Set.of("type", "order_id", "max_amount_cents"));
                yield new ActionRequest(action, requireString(entry, "order_id"), null, requirePositiveCents(entry));
            }
            default -> {
                allowOnly(entry, Set.of("type", "order_id"));
                yield new ActionRequest(action, requireString(entry, "order_id"), null, 0);
            }
        };
    }

    private static void allowOnly(Map<?, ?> entry, Set<String> allowed) {
        for (Object key : entry.keySet()) {
            if (!allowed.contains(key)) {
                throw invalidDetails("Unexpected authorization_details field: " + key);
            }
        }
    }

    private static String requireString(Map<?, ?> entry, String field) {
        if (!(entry.get(field) instanceof String value) || value.isBlank()) {
            throw invalidDetails("authorization_details needs " + field);
        }
        return value;
    }

    private static long requirePositiveCents(Map<?, ?> entry) {
        Object value = entry.get("max_amount_cents");
        if (!(value instanceof Long || value instanceof Integer) || ((Number) value).longValue() <= 0) {
            throw invalidDetails("max_amount_cents must be a positive whole number of cents");
        }
        return ((Number) value).longValue();
    }

    private static Denied invalidDetails(String description) {
        return new Denied("invalid_authorization_details", description);
    }
}
