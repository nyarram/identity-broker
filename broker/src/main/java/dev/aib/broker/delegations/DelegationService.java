package dev.aib.broker.delegations;

import dev.aib.broker.agents.Agent;
import dev.aib.broker.agents.AgentService;
import dev.aib.broker.audit.AuditLog;
import dev.aib.broker.audit.AuditLog.EventType;
import dev.aib.broker.audit.AuditLog.NewEvent;
import dev.aib.broker.config.BrokerProperties;
import dev.aib.broker.delegations.Delegation.TaskScope;
import dev.aib.broker.support.ApiException;
import dev.aib.broker.support.Ids;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DelegationService {

    /** JWT type of delegation tokens, so no resource server mistakes one for an access token. */
    public static final String DELEGATION_TOKEN_TYPE = "dlg+jwt";

    static final Duration DEFAULT_LIFETIME = Duration.ofHours(1);
    static final Duration MIN_LIFETIME = Duration.ofMinutes(1);
    static final Duration MAX_LIFETIME = Duration.ofHours(24);

    public record CreatedDelegation(Delegation delegation, String token) {}

    private final DelegationRepository delegations;
    private final AgentService agents;
    private final BrokerProperties properties;
    private final JwtEncoder jwtEncoder;
    private final AuditLog audit;
    private final Clock clock;

    DelegationService(
            DelegationRepository delegations,
            AgentService agents,
            BrokerProperties properties,
            JwtEncoder jwtEncoder,
            AuditLog audit,
            Clock clock) {
        this.delegations = delegations;
        this.agents = agents;
        this.properties = properties;
        this.jwtEncoder = jwtEncoder;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional
    public CreatedDelegation create(
            String userId, String agentId, String taskDescription, TaskScope taskScope, List<String> scopes,
            Long expiresInSeconds) {
        if (userId == null || userId.isBlank()) {
            throw ApiException.badRequest("user_id is required");
        }
        if (taskDescription == null || taskDescription.isBlank()) {
            throw ApiException.badRequest("task_description is required");
        }
        if (taskScope == null || taskScope.customerId() == null || taskScope.customerId().isBlank()) {
            throw ApiException.badRequest("task_scope.customer_id is required");
        }
        if (taskScope.orderIds() == null || taskScope.orderIds().isEmpty()) {
            throw ApiException.badRequest("task_scope.order_ids must list at least one order");
        }
        Agent agent = agents.get(agentId);
        if (agent.isDisabled()) {
            throw new ApiException(HttpStatus.CONFLICT, "agent_disabled", "Agent " + agentId + " is disabled");
        }
        Set<String> grantedScopes = validScopes(agent, scopes);
        Duration lifetime = lifetime(expiresInSeconds);

        Instant now = clock.instant();
        Delegation delegation = new Delegation(
                Ids.newId("dlg"), userId, agent.id(), taskDescription,
                new TaskScope(taskScope.customerId(), List.copyOf(taskScope.orderIds())),
                grantedScopes, now, now.plus(lifetime), null);
        String token = encode(delegation);
        delegations.insert(delegation, Ids.sha256(token));
        audit.append(new NewEvent(EventType.DELEGATION_CREATED, delegation.agentId(), delegation.userId(),
                delegation.id(), null, summary(delegation), null, null));
        return new CreatedDelegation(delegation, token);
    }

    private static Map<String, Object> summary(Delegation d) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("task_description", d.taskDescription());
        summary.put("customer_id", d.taskScope().customerId());
        summary.put("order_ids", d.taskScope().orderIds());
        summary.put("scopes", List.copyOf(d.scopes()));
        summary.put("expires_at", d.expiresAt().toString());
        return summary;
    }

    private Set<String> validScopes(Agent agent, List<String> scopes) {
        if (scopes == null || scopes.isEmpty()) {
            throw ApiException.badRequest("scopes must list at least one scope");
        }
        Set<String> allowed = properties.scopesFor(agent.allowedAudiences());
        for (String scope : scopes) {
            if (!allowed.contains(scope)) {
                throw ApiException.badRequest("Scope " + scope + " is not available to agent " + agent.id());
            }
        }
        return new TreeSet<>(scopes);
    }

    private static Duration lifetime(Long expiresInSeconds) {
        if (expiresInSeconds == null) {
            return DEFAULT_LIFETIME;
        }
        Duration lifetime = Duration.ofSeconds(expiresInSeconds);
        if (lifetime.compareTo(MIN_LIFETIME) < 0 || lifetime.compareTo(MAX_LIFETIME) > 0) {
            throw ApiException.badRequest("expires_in must be between 60 and 86400 seconds");
        }
        return lifetime;
    }

    /** The delegation token's audience is the broker itself, so it is useless against any API. */
    private String encode(Delegation d) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(properties.issuer())
                .subject(d.userId())
                .audience(List.of(properties.issuer()))
                .issuedAt(d.createdAt())
                .expiresAt(d.expiresAt())
                .id(UUID.randomUUID().toString())
                .claim("client_id", d.agentId())
                .claim("delegation_id", d.id())
                .claim("scope", String.join(" ", d.scopes()))
                .build();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.ES256).type(DELEGATION_TOKEN_TYPE).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
