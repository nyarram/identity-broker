package dev.aib.broker.approvals;

import dev.aib.broker.approvals.Approval.Status;
import dev.aib.broker.audit.AuditLog;
import dev.aib.broker.audit.AuditLog.EventType;
import dev.aib.broker.audit.AuditLog.NewEvent;
import dev.aib.broker.delegations.Delegation;
import dev.aib.broker.policy.ActionRequest;
import dev.aib.broker.support.ApiException;
import dev.aib.broker.support.CanonicalJson;
import dev.aib.broker.support.Ids;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Human approval for requests that policy allows only with one. The pattern follows the
 * device flow (RFC 8628): the token endpoint answers {@code authorization_pending}, the agent
 * polls, and retries with the approval id once a human has approved.
 */
@Service
public class ApprovalService {

    /** How long a human has to decide. */
    static final Duration DECISION_WINDOW = Duration.ofMinutes(10);
    /** How long the agent has to collect its token after approval. */
    static final Duration COLLECTION_WINDOW = Duration.ofMinutes(5);

    private final ApprovalRepository approvals;
    private final AuditLog audit;
    private final Clock clock;

    ApprovalService(ApprovalRepository approvals, AuditLog audit, Clock clock) {
        this.approvals = approvals;
        this.audit = audit;
        this.clock = clock;
    }

    /** Opens an approval request, or returns the pending one for this exact request. */
    @Transactional
    public Approval requestOrReuse(
            String agentId, Delegation delegation, String resource, ActionRequest action, String policyReason) {
        Instant now = clock.instant();
        String hash = requestHash(agentId, delegation.id(), resource, action);
        Optional<Approval> pending = approvals.findPending(agentId, delegation.id(), hash, now);
        if (pending.isPresent()) {
            return pending.get();
        }
        Approval approval = new Approval(Ids.newId("apr"), delegation.id(), agentId, delegation.userId(), hash,
                resource, action.toAuthorizationDetail(), policyReason, Status.PENDING, now,
                now.plus(DECISION_WINDOW), null, null, null);
        approvals.insert(approval);
        audit.append(new NewEvent(EventType.APPROVAL_REQUESTED, agentId, delegation.userId(), delegation.id(), null,
                summary(approval), null, policyReason));
        return approval;
    }

    public Optional<Approval> find(String id) {
        return approvals.findById(id);
    }

    /** Marks an approved approval as used. False if it was already used or has expired. */
    public boolean consume(String id) {
        return approvals.markUsed(id, clock.instant());
    }

    public List<Approval> pending() {
        return approvals.findPendingAll(clock.instant());
    }

    @Transactional
    public Approval approve(String id, String decidedBy) {
        return decide(id, Status.APPROVED, decidedBy, EventType.APPROVED);
    }

    @Transactional
    public Approval deny(String id, String decidedBy) {
        return decide(id, Status.DENIED, decidedBy, EventType.DENIED_BY_HUMAN);
    }

    private Approval decide(String id, Status decision, String decidedBy, EventType event) {
        Approval approval = approvals.findById(id).orElseThrow(() -> ApiException.notFound("No approval " + id));
        Instant now = clock.instant();
        Status current = approval.statusAt(now);
        if (current != Status.PENDING) {
            throw new ApiException(HttpStatus.CONFLICT, "approval_not_pending", "Approval " + id + " is " + current.value());
        }
        String by = decidedBy == null || decidedBy.isBlank() ? "admin" : decidedBy;
        if (!approvals.decide(id, decision, by, now, now.plus(COLLECTION_WINDOW))) {
            throw new ApiException(HttpStatus.CONFLICT, "approval_not_pending", "Approval " + id + " was decided concurrently");
        }
        audit.append(new NewEvent(event, approval.agentId(), approval.userId(), approval.delegationId(), null,
                summary(approval), decision == Status.APPROVED ? "permit" : "deny", "Decided by " + by));
        return approvals.findById(id).orElseThrow();
    }

    /** Binds an approval to the exact request it was granted for. */
    public static String requestHash(String agentId, String delegationId, String resource, ActionRequest action) {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("agent_id", agentId);
        request.put("delegation_id", delegationId);
        request.put("resource", resource);
        request.put("authorization_details", action.toAuthorizationDetail());
        return Ids.sha256(CanonicalJson.write(request));
    }

    private static Map<String, Object> summary(Approval a) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("approval_id", a.id());
        summary.put("resource", a.resource());
        summary.put("authorization_details", a.action());
        return summary;
    }
}
