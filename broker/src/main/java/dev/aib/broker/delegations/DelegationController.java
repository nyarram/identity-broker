package dev.aib.broker.delegations;

import com.fasterxml.jackson.annotation.JsonProperty;
import dev.aib.broker.delegations.Delegation.TaskScope;
import dev.aib.broker.delegations.DelegationService.CreatedDelegation;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
class DelegationController {

    record TaskScopeJson(
            @JsonProperty("customer_id") String customerId,
            @JsonProperty("order_ids") List<String> orderIds) {}

    record CreateDelegationRequest(
            @JsonProperty("user_id") String userId,
            @JsonProperty("agent_id") String agentId,
            @JsonProperty("task_description") String taskDescription,
            @JsonProperty("task_scope") TaskScopeJson taskScope,
            List<String> scopes,
            @JsonProperty("expires_in") Long expiresIn) {}

    record DelegationResponse(
            @JsonProperty("delegation_id") String delegationId,
            @JsonProperty("delegation_token") String delegationToken,
            @JsonProperty("agent_id") String agentId,
            @JsonProperty("user_id") String userId,
            Set<String> scopes,
            @JsonProperty("expires_at") Instant expiresAt) {}

    private final DelegationService delegations;

    DelegationController(DelegationService delegations) {
        this.delegations = delegations;
    }

    record RevokedResponse(
            @JsonProperty("delegation_id") String delegationId,
            @JsonProperty("revoked_at") Instant revokedAt) {}

    @PostMapping("/admin/delegations/{id}/revoke")
    RevokedResponse revoke(@PathVariable String id) {
        Delegation d = delegations.revoke(id);
        return new RevokedResponse(d.id(), d.revokedAt());
    }

    @PostMapping("/delegations")
    @ResponseStatus(HttpStatus.CREATED)
    DelegationResponse create(@RequestBody CreateDelegationRequest request) {
        TaskScopeJson scope = request.taskScope();
        CreatedDelegation created = delegations.create(
                request.userId(),
                request.agentId(),
                request.taskDescription(),
                scope == null ? null : new TaskScope(scope.customerId(), scope.orderIds()),
                request.scopes(),
                request.expiresIn());
        Delegation d = created.delegation();
        return new DelegationResponse(d.id(), created.token(), d.agentId(), d.userId(), d.scopes(), d.expiresAt());
    }
}
