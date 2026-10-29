package dev.aib.broker.delegations;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/** A human's grant of one task to one agent. Exchanged for access tokens, never sent to APIs. */
public record Delegation(
        String id,
        String userId,
        String agentId,
        String taskDescription,
        TaskScope taskScope,
        Set<String> scopes,
        Instant createdAt,
        Instant expiresAt,
        Instant revokedAt) {

    /** The data the task is limited to. Policy (M2) checks requests against it. */
    public record TaskScope(String customerId, List<String> orderIds) {}

    public boolean isActive(Instant now) {
        return revokedAt == null && now.isBefore(expiresAt);
    }
}
