package dev.aib.broker;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jwt.SignedJWT;
import dev.aib.broker.audit.AuditLog;
import dev.aib.broker.audit.AuditLog.EventType;
import dev.aib.broker.audit.AuditLog.NewEvent;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

class AuditIT extends IntegrationTestBase {

    @Autowired
    JdbcClient appJdbc; // connected as the restricted broker_app role

    @Autowired
    AuditLog auditLog;

    // ---- What gets recorded ----

    @Test
    void issuingATokenIsAudited() throws Exception {
        TestAgent agent = registerAgent("support-bot");
        Response delegation = createDelegation(agent, List.of("orders:read"), null);
        String accessToken = exchangeRead(agent, delegation.string("delegation_token")).string("access_token");
        String jti = SignedJWT.parse(accessToken).getJWTClaimsSet().getJWTID();

        Map<String, Object> event = event("select * from audit_events where jti = :v", jti);

        assertThat(event)
                .containsEntry("event_type", "token_issued")
                .containsEntry("agent_id", agent.id())
                .containsEntry("user_id", "alice")
                .containsEntry("delegation_id", delegation.string("delegation_id"))
                .containsEntry("decision", "permit")
                .containsEntry("reason", "Permitted by read-task-orders");
        assertThat(event.get("request").toString()).contains("\"order_id\": \"1042\"");
    }

    @Test
    void policyDenialsAreAuditedWithTheReason() {
        TestAgent agent = registerAgent("support-bot");
        Response delegation = createDelegation(agent, List.of("orders:delete"), null);

        exchange(agent, delegation.string("delegation_token"), "orders:delete", delete("1042"));

        Map<String, Object> event = event(
                "select * from audit_events where delegation_id = :v and event_type = 'token_denied'",
                delegation.string("delegation_id"));
        assertThat(event)
                .containsEntry("agent_id", agent.id())
                .containsEntry("user_id", "alice")
                .containsEntry("decision", "deny")
                .containsEntry("reason", "access_denied: Forbidden by never-delete");
    }

    @Test
    void failedClientAuthenticationIsAuditedWithoutTrustingTheClaimedAgent() {
        TestAgent agent = registerAgent("support-bot");
        Map<String, String> form = exchangeForm(agent, delegationToken(agent, "orders:read"), "orders:read", read("1042"));
        form.put("client_assertion", clientAssertion(agent.id(), newKey(), ISSUER + "/oauth2/token", Duration.ofMinutes(1)));

        postForm("/oauth2/token", form);

        Map<String, Object> event = event(
                "select * from audit_events where event_type = 'token_denied' and request->>'client_id' = :v", agent.id());
        assertThat(event.get("agent_id")).isNull();
        assertThat((String) event.get("reason")).startsWith("invalid_client");
    }

    @Test
    void adminActionsAreAudited() {
        TestAgent agent = registerAgent("support-bot");
        Response delegation = createDelegation(agent, List.of("orders:read"), null);

        assertThat(event("select * from audit_events where event_type = 'agent_registered' and agent_id = :v", agent.id()))
                .isNotNull();
        assertThat(event("select * from audit_events where event_type = 'delegation_created' and delegation_id = :v",
                delegation.string("delegation_id")))
                .containsEntry("user_id", "alice");
    }

    @Test
    void auditListingRequiresTheAdminToken() {
        assertThat(get("/admin/audit").status()).isEqualTo(401);
        assertThat(getAsAdmin("/admin/audit?limit=5").status()).isEqualTo(200);
    }

    // ---- Tamper evidence ----

    @Test
    void verifyPassesOnAnUntouchedLog() {
        registerAgent("support-bot");

        Response verify = getAsAdmin("/admin/audit/verify");

        assertThat(verify.json()).containsEntry("valid", true).containsEntry("first_broken_seq", null);
        assertThat(((Number) verify.json().get("events_checked")).longValue()).isPositive();
    }

    @Test
    void editingOneRowIsReportedAtThatRow() {
        registerAgent("support-bot");
        registerAgent("support-bot-2");
        long seq = latestSeq() - 1;
        JdbcClient owner = ownerJdbc();
        String original = owner.sql("select agent_id from audit_events where seq = :seq").param("seq", seq).query(String.class).single();
        try {
            owner.sql("update audit_events set agent_id = 'agt_someone_else' where seq = :seq").param("seq", seq).update();

            Response verify = getAsAdmin("/admin/audit/verify");

            assertThat(verify.json()).containsEntry("valid", false);
            assertThat(((Number) verify.json().get("first_broken_seq")).longValue()).isEqualTo(seq);
            assertThat(verify.string("problem")).isEqualTo("Hash does not match the event's contents");
        } finally {
            owner.sql("update audit_events set agent_id = :a where seq = :seq").param("a", original).param("seq", seq).update();
        }
        assertThat(getAsAdmin("/admin/audit/verify").json()).containsEntry("valid", true);
    }

    @Test
    void deletingARowIsReported() {
        registerAgent("support-bot");
        registerAgent("support-bot-2");
        long seq = latestSeq() - 1;
        JdbcClient owner = ownerJdbc();
        owner.sql("create table audit_backup as select * from audit_events where seq = :seq").param("seq", seq).update();
        try {
            owner.sql("delete from audit_events where seq = :seq").param("seq", seq).update();

            Response verify = getAsAdmin("/admin/audit/verify");

            assertThat(verify.json()).containsEntry("valid", false);
            assertThat(((Number) verify.json().get("first_broken_seq")).longValue()).isEqualTo(seq);
            assertThat(verify.string("problem")).isEqualTo("Event is missing");
        } finally {
            owner.sql("insert into audit_events select * from audit_backup").update();
            owner.sql("drop table audit_backup").update();
        }
        assertThat(getAsAdmin("/admin/audit/verify").json()).containsEntry("valid", true);
    }

    @Test
    void theBrokersDatabaseRoleCanNeitherEditNorDeleteAuditEvents() {
        registerAgent("support-bot");

        assertThatThrownBy(() -> appJdbc.sql("update audit_events set reason = 'x'").update())
                .rootCause().hasMessageContaining("permission denied");
        assertThatThrownBy(() -> appJdbc.sql("delete from audit_events").update())
                .rootCause().hasMessageContaining("permission denied");
        assertThatThrownBy(() -> appJdbc.sql("truncate audit_events").update())
                .rootCause().hasMessageContaining("permission denied");
    }

    @Test
    void concurrentAppendsKeepTheChainIntact() throws Exception {
        long before = latestSeq();
        int threads = 8;
        int perThread = 25;
        try (ExecutorService pool = Executors.newFixedThreadPool(threads)) {
            List<Future<?>> futures = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                int thread = t;
                futures.add(pool.submit(() -> {
                    for (int i = 0; i < perThread; i++) {
                        auditLog.append(new NewEvent(EventType.AGENT_DISABLED, "agt_load_" + thread, null, null, null,
                                Map.of("i", (long) i), null, null));
                    }
                }));
            }
            for (Future<?> f : futures) {
                f.get();
            }
        }

        assertThat(latestSeq()).isEqualTo(before + threads * perThread);
        assertThat(auditLog.verify().valid()).isTrue();
    }

    // ---- Helpers ----

    private Map<String, Object> event(String sql, String value) {
        return ownerJdbc().sql(sql + " order by seq desc limit 1").param("v", value).query().singleRow();
    }

    private static long latestSeq() {
        Long seq = ownerJdbc().sql("select max(seq) from audit_events").query(Long.class).single();
        return seq == null ? 0 : seq;
    }
}
