package dev.aib.broker.approvals;

import com.fasterxml.jackson.annotation.JsonProperty;
import dev.aib.broker.agents.Agent;
import dev.aib.broker.agents.AgentRepository;
import dev.aib.broker.delegations.Delegation;
import dev.aib.broker.delegations.DelegationRepository;
import dev.aib.broker.support.ApiException;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ApprovalController {

    /** What a polling agent sees: only the status. The id is an unguessable capability. */
    record ApprovalStatus(
            @JsonProperty("approval_id") String approvalId,
            String status,
            @JsonProperty("expires_at") Instant expiresAt) {}

    /** What the human approving sees: enough to make an informed decision. */
    record ApprovalView(
            @JsonProperty("approval_id") String approvalId,
            String status,
            @JsonProperty("agent_id") String agentId,
            @JsonProperty("agent_name") String agentName,
            @JsonProperty("user_id") String userId,
            @JsonProperty("delegation_id") String delegationId,
            @JsonProperty("task_description") String taskDescription,
            String resource,
            Map<String, Object> action,
            @JsonProperty("policy_reason") String policyReason,
            @JsonProperty("created_at") Instant createdAt,
            @JsonProperty("expires_at") Instant expiresAt,
            @JsonProperty("decided_by") String decidedBy) {}

    record DecisionRequest(@JsonProperty("decided_by") String decidedBy) {}

    private final ApprovalService approvals;
    private final AgentRepository agents;
    private final DelegationRepository delegations;
    private final Clock clock;

    ApprovalController(ApprovalService approvals, AgentRepository agents, DelegationRepository delegations, Clock clock) {
        this.approvals = approvals;
        this.agents = agents;
        this.delegations = delegations;
        this.clock = clock;
    }

    @GetMapping("/approvals/{id}")
    ApprovalStatus status(@PathVariable String id) {
        Approval a = approvals.find(id).orElseThrow(() -> ApiException.notFound("No approval " + id));
        return new ApprovalStatus(a.id(), a.statusAt(clock.instant()).value(), a.expiresAt());
    }

    @GetMapping("/admin/approvals")
    List<ApprovalView> pending() {
        return approvals.pending().stream().map(this::view).toList();
    }

    @PostMapping("/admin/approvals/{id}/approve")
    ApprovalView approve(@PathVariable String id, @RequestBody(required = false) DecisionRequest body) {
        return view(approvals.approve(id, body == null ? null : body.decidedBy()));
    }

    @PostMapping("/admin/approvals/{id}/deny")
    ApprovalView deny(@PathVariable String id, @RequestBody(required = false) DecisionRequest body) {
        return view(approvals.deny(id, body == null ? null : body.decidedBy()));
    }

    private ApprovalView view(Approval a) {
        String agentName = agents.findById(a.agentId()).map(Agent::name).orElse(null);
        String task = delegations.findById(a.delegationId()).map(Delegation::taskDescription).orElse(null);
        return new ApprovalView(a.id(), a.statusAt(clock.instant()).value(), a.agentId(), agentName, a.userId(),
                a.delegationId(), task, a.resource(), a.action(), a.policyReason(), a.createdAt(), a.expiresAt(),
                a.decidedBy());
    }
}
