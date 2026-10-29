package dev.aib.broker.approvals;

import java.time.Instant;
import java.util.Map;

/** A pending, decided or used human approval for one exact token request. */
public record Approval(
        String id,
        String delegationId,
        String agentId,
        String userId,
        String requestHash,
        String resource,
        Map<String, Object> action,
        String policyReason,
        Status status,
        Instant createdAt,
        Instant expiresAt,
        Instant decidedAt,
        String decidedBy,
        Instant usedAt) {

    /** Stored states. EXPIRED is never stored: it is derived from expires_at. */
    public enum Status {
        PENDING, APPROVED, DENIED, USED, EXPIRED;

        public String value() {
            return name().toLowerCase();
        }

        static Status parse(String value) {
            return valueOf(value.toUpperCase());
        }
    }

    /**
     * The status as of {@code now}. A pending approval nobody acted on, or an approved one
     * the agent never collected, expires.
     */
    public Status statusAt(Instant now) {
        boolean expired = !now.isBefore(expiresAt);
        return switch (status) {
            case PENDING, APPROVED -> expired ? Status.EXPIRED : status;
            default -> status;
        };
    }
}
