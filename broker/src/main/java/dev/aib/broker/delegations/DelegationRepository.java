package dev.aib.broker.delegations;

import com.nimbusds.jose.util.JSONObjectUtils;
import dev.aib.broker.delegations.Delegation.TaskScope;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.ParseException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class DelegationRepository {

    private final JdbcClient jdbc;

    DelegationRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    void insert(Delegation d, String tokenHash) {
        jdbc.sql("""
                insert into delegations
                    (id, user_id, agent_id, task_description, task_scope, scopes, token_hash, created_at, expires_at)
                values
                    (:id, :userId, :agentId, :task, cast(:taskScope as jsonb), :scopes, :tokenHash, :createdAt, :expiresAt)
                """)
                .param("id", d.id())
                .param("userId", d.userId())
                .param("agentId", d.agentId())
                .param("task", d.taskDescription())
                .param("taskScope", toJson(d.taskScope()))
                .param("scopes", d.scopes().toArray(String[]::new))
                .param("tokenHash", tokenHash)
                .param("createdAt", Timestamp.from(d.createdAt()))
                .param("expiresAt", Timestamp.from(d.expiresAt()))
                .update();
    }

    public Optional<Delegation> findById(String id) {
        return jdbc.sql("select * from delegations where id = :id")
                .param("id", id)
                .query(DelegationRepository::map)
                .optional();
    }

    public Optional<Delegation> findByTokenHash(String tokenHash) {
        return jdbc.sql("select * from delegations where token_hash = :hash")
                .param("hash", tokenHash)
                .query(DelegationRepository::map)
                .optional();
    }

    public boolean revoke(String id, Instant at) {
        return jdbc.sql("update delegations set revoked_at = :at where id = :id and revoked_at is null")
                .param("at", Timestamp.from(at))
                .param("id", id)
                .update() == 1;
    }

    private static String toJson(TaskScope scope) {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("customer_id", scope.customerId());
        json.put("order_ids", scope.orderIds());
        return JSONObjectUtils.toJSONString(json);
    }

    private static TaskScope fromJson(String json) throws SQLException {
        try {
            Map<String, Object> map = JSONObjectUtils.parse(json);
            return new TaskScope(
                    JSONObjectUtils.getString(map, "customer_id"),
                    List.of(JSONObjectUtils.getStringArray(map, "order_ids")));
        } catch (ParseException e) {
            throw new SQLException("Stored task_scope is not valid JSON", e);
        }
    }

    private static Delegation map(ResultSet rs, int row) throws SQLException {
        Timestamp revokedAt = rs.getTimestamp("revoked_at");
        return new Delegation(
                rs.getString("id"),
                rs.getString("user_id"),
                rs.getString("agent_id"),
                rs.getString("task_description"),
                fromJson(rs.getString("task_scope")),
                Set.of((String[]) rs.getArray("scopes").getArray()),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("expires_at").toInstant(),
                revokedAt == null ? null : revokedAt.toInstant());
    }
}
