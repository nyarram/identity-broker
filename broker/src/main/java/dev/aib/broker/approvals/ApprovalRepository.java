package dev.aib.broker.approvals;

import com.nimbusds.jose.util.JSONObjectUtils;
import dev.aib.broker.approvals.Approval.Status;
import dev.aib.broker.support.CanonicalJson;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
class ApprovalRepository {

    private final JdbcClient jdbc;

    ApprovalRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    void insert(Approval a) {
        jdbc.sql("""
                insert into approvals (id, delegation_id, agent_id, user_id, request_hash, resource, action,
                                       policy_reason, status, created_at, expires_at)
                values (:id, :delegationId, :agentId, :userId, :requestHash, :resource, cast(:action as jsonb),
                        :policyReason, :status, :createdAt, :expiresAt)
                """)
                .param("id", a.id())
                .param("delegationId", a.delegationId())
                .param("agentId", a.agentId())
                .param("userId", a.userId())
                .param("requestHash", a.requestHash())
                .param("resource", a.resource())
                .param("action", CanonicalJson.write(a.action()))
                .param("policyReason", a.policyReason())
                .param("status", a.status().value())
                .param("createdAt", Timestamp.from(a.createdAt()))
                .param("expiresAt", Timestamp.from(a.expiresAt()))
                .update();
    }

    Optional<Approval> findById(String id) {
        return jdbc.sql("select * from approvals where id = :id").param("id", id).query(ApprovalRepository::map).optional();
    }

    /** A still-pending approval for the same request, so retries do not pile up new ones. */
    Optional<Approval> findPending(String agentId, String delegationId, String requestHash, Instant now) {
        return jdbc.sql("""
                select * from approvals
                where agent_id = :agentId and delegation_id = :delegationId and request_hash = :hash
                  and status = 'pending' and expires_at > :now
                order by created_at desc limit 1
                """)
                .param("agentId", agentId)
                .param("delegationId", delegationId)
                .param("hash", requestHash)
                .param("now", Timestamp.from(now))
                .query(ApprovalRepository::map)
                .optional();
    }

    List<Approval> findPendingAll(Instant now) {
        return jdbc.sql("select * from approvals where status = 'pending' and expires_at > :now order by created_at")
                .param("now", Timestamp.from(now))
                .query(ApprovalRepository::map)
                .list();
    }

    /** Records a decision only if the approval is still pending and unexpired. */
    boolean decide(String id, Status decision, String decidedBy, Instant now, Instant newExpiry) {
        return jdbc.sql("""
                update approvals set status = :status, decided_by = :by, decided_at = :now, expires_at = :expiresAt
                where id = :id and status = 'pending' and expires_at > :now
                """)
                .param("status", decision.value())
                .param("by", decidedBy)
                .param("now", Timestamp.from(now))
                .param("expiresAt", Timestamp.from(newExpiry))
                .param("id", id)
                .update() == 1;
    }

    /** Consumes an approved approval. Only one concurrent caller can win. */
    boolean markUsed(String id, Instant now) {
        return jdbc.sql("""
                update approvals set status = 'used', used_at = :now
                where id = :id and status = 'approved' and expires_at > :now
                """)
                .param("now", Timestamp.from(now))
                .param("id", id)
                .update() == 1;
    }

    private static Approval map(ResultSet rs, int row) throws SQLException {
        try {
            return new Approval(
                    rs.getString("id"),
                    rs.getString("delegation_id"),
                    rs.getString("agent_id"),
                    rs.getString("user_id"),
                    rs.getString("request_hash"),
                    rs.getString("resource"),
                    JSONObjectUtils.parse(rs.getString("action")),
                    rs.getString("policy_reason"),
                    Status.parse(rs.getString("status")),
                    rs.getTimestamp("created_at").toInstant(),
                    rs.getTimestamp("expires_at").toInstant(),
                    instant(rs.getTimestamp("decided_at")),
                    rs.getString("decided_by"),
                    instant(rs.getTimestamp("used_at")));
        } catch (ParseException e) {
            throw new SQLException("Stored approval action is not valid JSON", e);
        }
    }

    private static Instant instant(Timestamp t) {
        return t == null ? null : t.toInstant();
    }
}
