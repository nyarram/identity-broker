package dev.aib.broker;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.util.JSONArrayUtils;
import com.nimbusds.jwt.SignedJWT;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

/** The human approval flow for a $120 refund on task order 1042. */
class ApprovalIT extends IntegrationTestBase {

    static final String REFUND_120 = refund("1042", 12000);

    @Autowired
    JdbcClient jdbc;

    @Test
    void a120DollarRefundIsIssuedAfterAHumanApprovesIt() throws Exception {
        TestAgent agent = registerAgent("support-bot");
        String delegationToken = delegationToken(agent, "orders:refund");

        Response pending = exchange(agent, delegationToken, "orders:refund", REFUND_120);

        assertThat(pending.status()).isEqualTo(400);
        assertThat(pending.string("error")).isEqualTo("authorization_pending");
        String approvalId = pending.string("approval_id");
        assertThat(pending.string("approval_uri")).isEqualTo(ISSUER + "/approvals/" + approvalId);
        assertThat(((Number) pending.json().get("expires_in")).longValue()).isBetween(590L, 600L);
        assertThat(get("/approvals/" + approvalId).string("status")).isEqualTo("pending");

        Response approved = postJson("/admin/approvals/" + approvalId + "/approve", Map.of("decided_by", "alice"), ADMIN_TOKEN);
        assertThat(approved.string("status")).isEqualTo("approved");
        assertThat(get("/approvals/" + approvalId).string("status")).isEqualTo("approved");

        Response issued = redeem(agent, delegationToken, REFUND_120, approvalId);

        assertThat(issued.status()).as(issued.toString()).isEqualTo(200);
        assertThat(SignedJWT.parse(issued.string("access_token")).getJWTClaimsSet().getClaim("authorization_details"))
                .isEqualTo(List.of(Map.of("type", "refund", "order_id", "1042", "max_amount_cents", 12000L)));
        assertThat(get("/approvals/" + approvalId).string("status")).isEqualTo("used");
    }

    @Test
    void retriesReuseThePendingApprovalInsteadOfOpeningNewOnes() {
        TestAgent agent = registerAgent("support-bot");
        String delegationToken = delegationToken(agent, "orders:refund");

        String first = exchange(agent, delegationToken, "orders:refund", REFUND_120).string("approval_id");
        String second = exchange(agent, delegationToken, "orders:refund", REFUND_120).string("approval_id");

        assertThat(second).isEqualTo(first);
    }

    @Test
    void retryingBeforeTheDecisionIsStillPending() {
        TestAgent agent = registerAgent("support-bot");
        String delegationToken = delegationToken(agent, "orders:refund");
        String approvalId = exchange(agent, delegationToken, "orders:refund", REFUND_120).string("approval_id");

        Response early = redeem(agent, delegationToken, REFUND_120, approvalId);

        assertThat(early.string("error")).isEqualTo("authorization_pending");
        assertThat(early.string("approval_id")).isEqualTo(approvalId);
    }

    @Test
    void anApprovalCanBeUsedOnceAndOnlyForTheApprovedRequest() {
        TestAgent agent = registerAgent("support-bot");
        String delegationToken = delegationToken(agent, "orders:refund");
        String approvalId = approve(exchange(agent, delegationToken, "orders:refund", REFUND_120).string("approval_id"));

        Response different = redeem(agent, delegationToken, refund("1042", 12001), approvalId);
        Response used = redeem(agent, delegationToken, REFUND_120, approvalId);
        Response reused = redeem(agent, delegationToken, REFUND_120, approvalId);

        assertThat(different.string("error")).isEqualTo("invalid_grant");
        assertThat(different.string("error_description")).contains("different request");
        assertThat(used.status()).isEqualTo(200);
        assertThat(reused.string("error")).isEqualTo("invalid_grant");
    }

    @Test
    void aDeniedRequestIsNotIssued() {
        TestAgent agent = registerAgent("support-bot");
        String delegationToken = delegationToken(agent, "orders:refund");
        String approvalId = exchange(agent, delegationToken, "orders:refund", REFUND_120).string("approval_id");

        postJson("/admin/approvals/" + approvalId + "/deny", Map.of(), ADMIN_TOKEN);
        Response retry = redeem(agent, delegationToken, REFUND_120, approvalId);

        assertThat(get("/approvals/" + approvalId).string("status")).isEqualTo("denied");
        assertThat(retry.string("error")).isEqualTo("access_denied");
        assertThat(retry.string("error_description")).contains("A human denied");
    }

    @Test
    void anApprovalNobodyActsOnExpiresAndTheRequestIsDenied() {
        TestAgent agent = registerAgent("support-bot");
        String delegationToken = delegationToken(agent, "orders:refund");
        String approvalId = exchange(agent, delegationToken, "orders:refund", REFUND_120).string("approval_id");
        // Ten minutes pass
        jdbc.sql("update approvals set expires_at = now() - interval '1 second' where id = :id").param("id", approvalId).update();

        Response lateApproval = postJson("/admin/approvals/" + approvalId + "/approve", Map.of(), ADMIN_TOKEN);
        Response retry = redeem(agent, delegationToken, REFUND_120, approvalId);

        assertThat(get("/approvals/" + approvalId).string("status")).isEqualTo("expired");
        assertThat(lateApproval.status()).isEqualTo(409);
        assertThat(retry.string("error")).isEqualTo("access_denied");
        assertThat(retry.string("error_description")).contains("expired");
    }

    @Test
    void thePendingListShowsWhatTheHumanIsApproving() throws Exception {
        TestAgent agent = registerAgent("support-bot");
        String approvalId = exchange(agent, delegationToken(agent, "orders:refund"), "orders:refund", REFUND_120)
                .string("approval_id");

        List<Object> pending = JSONArrayUtils.parse(getRawAsAdmin("/admin/approvals"));

        Map<?, ?> view = pending.stream().map(Map.class::cast)
                .filter(a -> approvalId.equals(a.get("approval_id"))).findFirst().orElseThrow();
        assertThat(view.get("agent_name")).isEqualTo("support-bot");
        assertThat(view.get("user_id")).isEqualTo("alice");
        assertThat(view.get("task_description")).isEqualTo("Help Alice with her running shoes order");
        assertThat(view.get("action")).isEqualTo(Map.of("type", "refund", "order_id", "1042", "max_amount_cents", 12000L));
        assertThat((String) view.get("policy_reason")).contains("refund-task-orders");
    }

    @Test
    void theApprovalLifecycleIsAudited() {
        TestAgent agent = registerAgent("support-bot");
        String delegationToken = delegationToken(agent, "orders:refund");
        String approvalId = approve(exchange(agent, delegationToken, "orders:refund", REFUND_120).string("approval_id"));
        redeem(agent, delegationToken, REFUND_120, approvalId);

        List<String> events = jdbc.sql("""
                select event_type from audit_events
                where agent_id = :agent and event_type in ('approval_requested', 'approved', 'token_issued')
                order by seq
                """).param("agent", agent.id()).query(String.class).list();
        String issuedReason = jdbc.sql("select reason from audit_events where agent_id = :agent and event_type = 'token_issued'")
                .param("agent", agent.id()).query(String.class).single();

        assertThat(events).containsExactly("approval_requested", "approved", "token_issued");
        assertThat(issuedReason).contains(approvalId).contains("approved by admin");
    }

    private Response redeem(TestAgent agent, String delegationToken, String details, String approvalId) {
        Map<String, String> form = exchangeForm(agent, delegationToken, "orders:refund", details);
        form.put("approval_id", approvalId);
        return postForm("/oauth2/token", form);
    }

    private String approve(String approvalId) {
        postJson("/admin/approvals/" + approvalId + "/approve", Map.of(), ADMIN_TOKEN);
        return approvalId;
    }
}
