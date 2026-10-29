package dev.aib.broker.agents;

import com.nimbusds.jose.jwk.ECKey;
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
public class AgentRepository {

    private final JdbcClient jdbc;

    AgentRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    void insert(Agent agent) {
        jdbc.sql("""
                insert into agents (id, name, public_jwk, allowed_audiences, created_at)
                values (:id, :name, cast(:jwk as jsonb), :audiences, :createdAt)
                """)
                .param("id", agent.id())
                .param("name", agent.name())
                .param("jwk", agent.publicKey().toJSONString())
                .param("audiences", agent.allowedAudiences().toArray(String[]::new))
                .param("createdAt", Timestamp.from(agent.createdAt()))
                .update();
    }

    public Optional<Agent> findById(String id) {
        return jdbc.sql("select * from agents where id = :id").param("id", id).query(AgentRepository::map).optional();
    }

    boolean disable(String id, Instant at) {
        return jdbc.sql("update agents set disabled_at = :at where id = :id and disabled_at is null")
                .param("at", Timestamp.from(at))
                .param("id", id)
                .update() == 1;
    }

    private static Agent map(ResultSet rs, int row) throws SQLException {
        Timestamp disabledAt = rs.getTimestamp("disabled_at");
        return new Agent(
                rs.getString("id"),
                rs.getString("name"),
                parseKey(rs.getString("public_jwk")),
                List.of((String[]) rs.getArray("allowed_audiences").getArray()),
                rs.getTimestamp("created_at").toInstant(),
                disabledAt == null ? null : disabledAt.toInstant());
    }

    private static ECKey parseKey(String json) throws SQLException {
        try {
            return ECKey.parse(json);
        } catch (ParseException e) {
            throw new SQLException("Stored agent key is not a valid EC JWK", e);
        }
    }
}
