package dev.aib.broker.tokens;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import dev.aib.broker.approvals.Approval;
import dev.aib.broker.approvals.Approval.Status;
import dev.aib.broker.approvals.ApprovalService;
import dev.aib.broker.config.BrokerProperties;
import dev.aib.broker.delegations.Delegation;
import dev.aib.broker.delegations.Delegation.TaskScope;
import dev.aib.broker.policy.ActionRequest;
import dev.aib.broker.policy.ActionRequest.Action;
import dev.aib.broker.policy.PolicyEngine;
import dev.aib.broker.tokens.ExchangeRules.ApprovalPending;
import dev.aib.broker.tokens.ExchangeRules.Denied;
import dev.aib.broker.tokens.ExchangeRules.Grant;
import dev.aib.broker.tokens.ExchangeRules.Request;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ExchangeRulesTest {

    static final String ORDERS = "https://orders-api.example";
    static final String BILLING = "https://billing.example";
    static final Instant NOW = Instant.parse("2026-10-29T12:00:00Z");
    static final Instant DEFAULT_EXPIRY = NOW.plus(Duration.ofMinutes(5));
    static final PolicyEngine POLICY = new PolicyEngine(Path.of("../policies"));

    static final String READ_1042 = "[{\"type\":\"read\",\"order_id\":\"1042\"}]";

    final ApprovalService approvals = mock(ApprovalService.class);

    final ExchangeRules rules = new ExchangeRules(new BrokerProperties(
            "http://broker.test",
            "x".repeat(32),
            null,
            Duration.ofMinutes(5),
            "../policies",
            List.of(
                    new BrokerProperties.Resource(ORDERS,
                            Set.of("orders:read", "orders:refund", "orders:cancel", "orders:delete")),
                    new BrokerProperties.Resource(BILLING, Set.of("billing:read")))),
            POLICY,
            approvals);

    final Delegation delegation = delegation(Set.of("orders:read", "orders:refund", "orders:delete"),
            NOW.plus(Duration.ofHours(1)), null);

    static Delegation delegation(Set<String> scopes, Instant expiresAt, Instant revokedAt) {
        return new Delegation("dlg_1", "alice", "agt_1", "Help with order 1042",
                new TaskScope("cust_alice", List.of("1042")), scopes,
                NOW.minus(Duration.ofHours(2)), expiresAt, revokedAt);
    }

    static Request request(String scope, String details) {
        return new Request("agt_1", scope.isEmpty() ? Set.of() : Set.of(scope.split(" ")), Set.of(ORDERS), Set.of(),
                details, null);
    }

    Grant evaluate(Request request) {
        return rules.evaluate(request, delegation, List.of(ORDERS), NOW, DEFAULT_EXPIRY);
    }

    // ---- Granted ----

    @Test
    void grantsOneActionOnATaskOrder() {
        Grant grant = evaluate(request("orders:read", READ_1042));

        assertThat(grant.audience()).isEqualTo(ORDERS);
        assertThat(grant.scopes()).containsExactly("orders:read");
        assertThat(grant.authorizationDetails()).containsExactly(Map.of("type", "read", "order_id", "1042"));
        assertThat(grant.expiresAt()).isEqualTo(DEFAULT_EXPIRY);
        assertThat(grant.policyReason()).isEqualTo("Permitted by read-task-orders");
    }

    @Test
    void grantsARefundUpToFiftyDollars() {
        Grant grant = evaluate(request("orders:refund", "[{\"type\":\"refund\",\"order_id\":\"1042\",\"max_amount_cents\":3000}]"));

        assertThat(grant.action()).isEqualTo(new ActionRequest(Action.REFUND, "1042", null, 3000));
        assertThat(grant.authorizationDetails().getFirst()).containsEntry("max_amount_cents", 3000L);
    }

    @Test
    void neverOutlivesTheDelegation() {
        Instant delegationExpiry = NOW.plus(Duration.ofMinutes(2));
        Delegation shortLived = delegation(Set.of("orders:read"), delegationExpiry, null);

        Grant grant = rules.evaluate(request("orders:read", READ_1042), shortLived, List.of(ORDERS), NOW, DEFAULT_EXPIRY);

        assertThat(grant.expiresAt()).isEqualTo(delegationExpiry);
    }

    // ---- Denied by policy ----

    @Test
    void deniesReadingAnOrderOutsideTheTask() {
        assertDenied(() -> evaluate(request("orders:read", "[{\"type\":\"read\",\"order_id\":\"1050\"}]")),
                "access_denied", "No policy permits: read order 1050");
    }

    @Test
    void deniesEveryDelete() {
        assertDenied(() -> evaluate(request("orders:delete", "[{\"type\":\"delete\",\"order_id\":\"1042\"}]")),
                "access_denied", "Forbidden by never-delete");
    }

    @Test
    void refundsAboveFiftyDollarsOpenAnApprovalRequest() {
        Approval pending = approval(Status.PENDING);
        when(approvals.requestOrReuse(eq("agt_1"), eq(delegation), eq(ORDERS), any(), any())).thenReturn(pending);

        assertThatThrownBy(() -> evaluate(request("orders:refund", REFUND_1042_120)))
                .isInstanceOfSatisfying(ApprovalPending.class, e -> {
                    assertThat(e.code()).isEqualTo("authorization_pending");
                    assertThat(e.approval()).isEqualTo(pending);
                });
    }

    // ---- Redeeming an approval ----

    @Test
    void anApprovedRequestIsIssuedOnceAndConsumesTheApproval() {
        Approval approved = approval(Status.APPROVED);
        when(approvals.find("apr_1")).thenReturn(Optional.of(approved));
        when(approvals.consume("apr_1")).thenReturn(true);

        Grant grant = evaluate(withApproval(REFUND_1042_120, "apr_1"));

        assertThat(grant.action().amountCents()).isEqualTo(12000);
        assertThat(grant.policyReason()).contains("Permitted with human approval by refund-task-orders").contains("apr_1");
        verify(approvals).consume("apr_1");
    }

    @Test
    void anApprovalOnlyCoversTheExactRequestItWasGrantedFor() {
        when(approvals.find("apr_1")).thenReturn(Optional.of(approval(Status.APPROVED)));

        // Approved for $120 on 1042; the agent now asks for $130
        String different = "[{\"type\":\"refund\",\"order_id\":\"1042\",\"max_amount_cents\":13000}]";
        assertDenied(() -> evaluate(withApproval(different, "apr_1")), "invalid_grant", "different request");
        verify(approvals, never()).consume(any());
    }

    @Test
    void pendingDeniedExpiredAndUsedApprovalsDoNotIssue() {
        when(approvals.find("apr_1")).thenReturn(Optional.of(approval(Status.PENDING)));
        assertThatThrownBy(() -> evaluate(withApproval(REFUND_1042_120, "apr_1"))).isInstanceOf(ApprovalPending.class);

        when(approvals.find("apr_1")).thenReturn(Optional.of(approval(Status.DENIED)));
        assertDenied(() -> evaluate(withApproval(REFUND_1042_120, "apr_1")), "access_denied", "denied");

        Approval stale = approval(Status.PENDING, NOW.minusSeconds(1));
        when(approvals.find("apr_1")).thenReturn(Optional.of(stale));
        assertDenied(() -> evaluate(withApproval(REFUND_1042_120, "apr_1")), "access_denied", "expired");

        when(approvals.find("apr_1")).thenReturn(Optional.of(approval(Status.USED)));
        assertDenied(() -> evaluate(withApproval(REFUND_1042_120, "apr_1")), "invalid_grant", "already been used");

        when(approvals.find("apr_1")).thenReturn(Optional.of(approval(Status.APPROVED)));
        when(approvals.consume("apr_1")).thenReturn(false); // lost a race with a concurrent retry
        assertDenied(() -> evaluate(withApproval(REFUND_1042_120, "apr_1")), "invalid_grant", "already been used");
    }

    @Test
    void unknownApprovalIdsAreRejected() {
        when(approvals.find("apr_missing")).thenReturn(Optional.empty());
        assertDenied(() -> evaluate(withApproval(REFUND_1042_120, "apr_missing")), "invalid_grant", "Unknown approval_id");
    }

    static final String REFUND_1042_120 = "[{\"type\":\"refund\",\"order_id\":\"1042\",\"max_amount_cents\":12000}]";

    static Request withApproval(String details, String approvalId) {
        return new Request("agt_1", Set.of("orders:refund"), Set.of(ORDERS), Set.of(), details, approvalId);
    }

    Approval approval(Status status) {
        return approval(status, NOW.plus(Duration.ofMinutes(5)));
    }

    Approval approval(Status status, Instant expiresAt) {
        ActionRequest action = new ActionRequest(Action.REFUND, "1042", null, 12000);
        return new Approval("apr_1", delegation.id(), "agt_1", "alice",
                ApprovalService.requestHash("agt_1", delegation.id(), ORDERS, action), ORDERS,
                action.toAuthorizationDetail(), "Needs human approval", status, NOW.minusSeconds(60), expiresAt,
                null, "alice", null);
    }

    // ---- Binding to the delegation ----

    @Test
    void rejectsADelegationIssuedToAnotherAgent() {
        Request other = new Request("agt_2", Set.of("orders:read"), Set.of(ORDERS), Set.of(), READ_1042, null);
        assertDenied(() -> evaluate(other), "invalid_grant", "different agent");
    }

    @Test
    void rejectsExpiredAndRevokedDelegations() {
        Delegation expired = delegation(delegation.scopes(), NOW.minusSeconds(1), null);
        Delegation revoked = delegation(delegation.scopes(), NOW.plus(Duration.ofHours(1)), NOW.minusSeconds(1));
        Request req = request("orders:read", READ_1042);

        assertDenied(() -> rules.evaluate(req, expired, List.of(ORDERS), NOW, DEFAULT_EXPIRY), "invalid_grant", "expired");
        assertDenied(() -> rules.evaluate(req, revoked, List.of(ORDERS), NOW, DEFAULT_EXPIRY), "invalid_grant", "revoked");
    }

    @Test
    void scopeMustBeExactlyTheActionsScopeAndWithinTheDelegation() {
        assertDenied(() -> evaluate(request("", READ_1042)), "invalid_scope", "scope is required");
        assertDenied(() -> evaluate(request("orders:refund", READ_1042)), "invalid_scope", "must request exactly orders:read");
        assertDenied(() -> evaluate(request("orders:read orders:refund", READ_1042)), "invalid_scope", "exactly");
        assertDenied(() -> evaluate(request("orders:cancel", "[{\"type\":\"cancel\",\"order_id\":\"1042\"}]")),
                "invalid_scope", "exceeds the delegation");
    }

    @Test
    void requiresExactlyOneResourceTheAgentIsRegisteredFor() {
        for (Set<String> resources : List.of(Set.<String>of(), Set.of(ORDERS, BILLING), Set.of(BILLING),
                Set.of("https://unknown.example"))) {
            Request req = new Request("agt_1", Set.of("orders:read"), resources, Set.of(), READ_1042, null);
            assertDenied(() -> evaluate(req), "invalid_target", "");
        }
    }

    @Test
    void rejectsTheAudienceParameter() {
        Request req = new Request("agt_1", Set.of("orders:read"), Set.of(ORDERS), Set.of(ORDERS), READ_1042, null);
        assertDenied(() -> evaluate(req), "invalid_target", "resource parameter");
    }

    // ---- authorization_details parsing ----

    @Test
    void parsesEachActionType() {
        assertThat(ExchangeRules.parseAction("[{\"type\":\"list\",\"customer_id\":\"cust_alice\"}]"))
                .isEqualTo(new ActionRequest(Action.LIST, null, "cust_alice", 0));
        assertThat(ExchangeRules.parseAction("[{\"type\":\"cancel\",\"order_id\":\"1042\"}]"))
                .isEqualTo(new ActionRequest(Action.CANCEL, "1042", null, 0));
    }

    @Test
    void rejectsMissingOrMalformedAuthorizationDetails() {
        for (String bad : List.of(
                "",
                "not json",
                "{\"type\":\"read\",\"order_id\":\"1042\"}",
                "[]",
                "[" + READ_1042.substring(1, READ_1042.length() - 1) + "," + READ_1042.substring(1, READ_1042.length() - 1) + "]",
                "[{\"order_id\":\"1042\"}]",
                "[{\"type\":\"teleport\",\"order_id\":\"1042\"}]",
                "[{\"type\":\"read\"}]",
                "[{\"type\":\"read\",\"order_id\":\"1042\",\"extra\":true}]",
                "[{\"type\":\"refund\",\"order_id\":\"1042\"}]",
                "[{\"type\":\"refund\",\"order_id\":\"1042\",\"max_amount_cents\":30.5}]",
                "[{\"type\":\"refund\",\"order_id\":\"1042\",\"max_amount_cents\":-1}]",
                "[{\"type\":\"list\"}]",
                "[{\"type\":\"read\",\"order_id\":\"" + "x".repeat(5000) + "\"}]")) {
            assertDenied(() -> ExchangeRules.parseAction(bad), "invalid_authorization_details", "");
        }
    }

    private static void assertDenied(Runnable call, String code, String messagePart) {
        assertThatThrownBy(call::run)
                .isInstanceOf(Denied.class)
                .hasMessageContaining(messagePart)
                .extracting(e -> ((Denied) e).code())
                .isEqualTo(code);
    }
}
