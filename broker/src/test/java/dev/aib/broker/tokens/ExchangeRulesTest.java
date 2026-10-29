package dev.aib.broker.tokens;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.aib.broker.config.BrokerProperties;
import dev.aib.broker.delegations.Delegation;
import dev.aib.broker.delegations.Delegation.TaskScope;
import dev.aib.broker.tokens.ExchangeRules.Denied;
import dev.aib.broker.tokens.ExchangeRules.Grant;
import dev.aib.broker.tokens.ExchangeRules.Request;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ExchangeRulesTest {

    static final String ORDERS = "https://orders-api.example";
    static final String BILLING = "https://billing.example";
    static final Instant NOW = Instant.parse("2026-10-29T12:00:00Z");
    static final Instant DEFAULT_EXPIRY = NOW.plus(Duration.ofMinutes(5));

    final ExchangeRules rules = new ExchangeRules(new BrokerProperties(
            "http://broker.test",
            "x".repeat(32),
            null,
            Duration.ofMinutes(5),
            List.of(
                    new BrokerProperties.Resource(ORDERS, Set.of("orders:read", "orders:refund", "orders:cancel")),
                    new BrokerProperties.Resource(BILLING, Set.of("billing:read")))));

    final Delegation delegation = new Delegation(
            "dlg_1", "alice", "agt_1", "Help with order 1042",
            new TaskScope("cust_alice", List.of("1042")),
            Set.of("orders:read", "orders:refund"),
            NOW.minus(Duration.ofMinutes(1)), NOW.plus(Duration.ofHours(1)), null);

    Request request(String agentId, Set<String> scopes, Set<String> resources) {
        return new Request(agentId, scopes, resources, Set.of(), null);
    }

    Grant evaluate(Request request) {
        return rules.evaluate(request, delegation, List.of(ORDERS), NOW, DEFAULT_EXPIRY);
    }

    @Test
    void grantsRequestedScopesWithinTheDelegation() {
        Grant grant = evaluate(request("agt_1", Set.of("orders:read"), Set.of(ORDERS)));

        assertThat(grant.audience()).isEqualTo(ORDERS);
        assertThat(grant.scopes()).containsExactly("orders:read");
        assertThat(grant.expiresAt()).isEqualTo(DEFAULT_EXPIRY);
        assertThat(grant.authorizationDetails()).isEmpty();
    }

    @Test
    void rejectsADelegationIssuedToAnotherAgent() {
        assertDenied(() -> evaluate(request("agt_2", Set.of("orders:read"), Set.of(ORDERS))), "invalid_grant");
    }

    @Test
    void rejectsExpiredAndRevokedDelegations() {
        Delegation expired = new Delegation(delegation.id(), "alice", "agt_1", "t", delegation.taskScope(),
                delegation.scopes(), NOW.minus(Duration.ofHours(2)), NOW.minus(Duration.ofSeconds(1)), null);
        Delegation revoked = new Delegation(delegation.id(), "alice", "agt_1", "t", delegation.taskScope(),
                delegation.scopes(), delegation.createdAt(), delegation.expiresAt(), NOW.minus(Duration.ofSeconds(1)));
        Request req = request("agt_1", Set.of("orders:read"), Set.of(ORDERS));

        assertDenied(() -> rules.evaluate(req, expired, List.of(ORDERS), NOW, DEFAULT_EXPIRY), "invalid_grant");
        assertDenied(() -> rules.evaluate(req, revoked, List.of(ORDERS), NOW, DEFAULT_EXPIRY), "invalid_grant");
    }

    @Test
    void requiresScopeAndRejectsScopeBeyondTheDelegation() {
        assertDenied(() -> evaluate(request("agt_1", Set.of(), Set.of(ORDERS))), "invalid_scope");
        assertDenied(() -> evaluate(request("agt_1", Set.of("orders:cancel"), Set.of(ORDERS))), "invalid_scope");
        assertDenied(() -> evaluate(request("agt_1", Set.of("orders:read", "orders:cancel"), Set.of(ORDERS))),
                "invalid_scope");
    }

    @Test
    void requiresExactlyOneResourceTheAgentIsRegisteredFor() {
        assertDenied(() -> evaluate(request("agt_1", Set.of("orders:read"), Set.of())), "invalid_target");
        assertDenied(() -> evaluate(request("agt_1", Set.of("orders:read"), Set.of(ORDERS, BILLING))), "invalid_target");
        assertDenied(() -> evaluate(request("agt_1", Set.of("orders:read"), Set.of(BILLING))), "invalid_target");
        assertDenied(() -> evaluate(request("agt_1", Set.of("orders:read"), Set.of("https://unknown.example"))),
                "invalid_target");
    }

    @Test
    void rejectsTheAudienceParameter() {
        Request req = new Request("agt_1", Set.of("orders:read"), Set.of(ORDERS), Set.of(ORDERS), null);
        assertDenied(() -> evaluate(req), "invalid_target");
    }

    @Test
    void neverOutlivesTheDelegation() {
        Instant delegationExpiry = NOW.plus(Duration.ofMinutes(2));
        Delegation shortLived = new Delegation(delegation.id(), "alice", "agt_1", "t", delegation.taskScope(),
                delegation.scopes(), delegation.createdAt(), delegationExpiry, null);

        Grant grant = rules.evaluate(request("agt_1", Set.of("orders:read"), Set.of(ORDERS)), shortLived,
                List.of(ORDERS), NOW, DEFAULT_EXPIRY);

        assertThat(grant.expiresAt()).isEqualTo(delegationExpiry);
    }

    @Test
    void carriesStructurallyValidAuthorizationDetails() {
        Request req = new Request("agt_1", Set.of("orders:refund"), Set.of(ORDERS), Set.of(),
                "[{\"type\":\"refund\",\"order_id\":\"1042\",\"max_amount_cents\":3000}]");

        Grant grant = evaluate(req);

        assertThat(grant.authorizationDetails()).hasSize(1);
        assertThat(grant.authorizationDetails().getFirst()).containsEntry("type", "refund").containsEntry("order_id", "1042");
    }

    @Test
    void rejectsMalformedAuthorizationDetails() {
        for (String bad : List.of("{\"type\":\"refund\"}", "[{\"order_id\":\"1042\"}]", "[\"refund\"]", "not json",
                "[{\"type\":\"" + "x".repeat(5000) + "\"}]")) {
            Request req = new Request("agt_1", Set.of("orders:refund"), Set.of(ORDERS), Set.of(), bad);
            assertDenied(() -> evaluate(req), "invalid_authorization_details");
        }
    }

    private static void assertDenied(Runnable call, String code) {
        assertThatThrownBy(call::run).isInstanceOf(Denied.class).extracting(e -> ((Denied) e).code()).isEqualTo(code);
    }
}
