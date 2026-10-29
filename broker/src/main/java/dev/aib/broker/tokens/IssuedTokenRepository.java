package dev.aib.broker.tokens;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
class IssuedTokenRepository {

    record IssuedToken(
            String jti,
            String delegationId,
            String agentId,
            String userId,
            String audience,
            Set<String> scopes,
            String claimsJson,
            Instant issuedAt,
            Instant expiresAt,
            Instant revokedAt) {}

    private final JdbcClient jdbc;

    IssuedTokenRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /** Inserts a newly issued token, or records its revocation if it already exists. */
    void upsert(IssuedToken t, String tokenHash) {
        jdbc.sql("""
                insert into issued_tokens
                    (jti, token_hash, delegation_id, agent_id, user_id, audience, scopes, claims,
                     issued_at, expires_at, revoked_at)
                values
                    (:jti, :tokenHash, :delegationId, :agentId, :userId, :audience, :scopes, cast(:claims as jsonb),
                     :issuedAt, :expiresAt, :revokedAt)
                on conflict (jti) do update
                    set revoked_at = coalesce(issued_tokens.revoked_at, excluded.revoked_at)
                """)
                .param("jti", t.jti())
                .param("tokenHash", tokenHash)
                .param("delegationId", t.delegationId())
                .param("agentId", t.agentId())
                .param("userId", t.userId())
                .param("audience", t.audience())
                .param("scopes", t.scopes().toArray(String[]::new))
                .param("claims", t.claimsJson())
                .param("issuedAt", Timestamp.from(t.issuedAt()))
                .param("expiresAt", Timestamp.from(t.expiresAt()))
                .param("revokedAt", t.revokedAt() == null ? null : Timestamp.from(t.revokedAt()))
                .update();
    }

    Optional<IssuedToken> findByTokenHash(String tokenHash) {
        return jdbc.sql("select * from issued_tokens where token_hash = :hash")
                .param("hash", tokenHash)
                .query(IssuedTokenRepository::map)
                .optional();
    }

    private static IssuedToken map(ResultSet rs, int row) throws SQLException {
        Timestamp revokedAt = rs.getTimestamp("revoked_at");
        return new IssuedToken(
                rs.getString("jti"),
                rs.getString("delegation_id"),
                rs.getString("agent_id"),
                rs.getString("user_id"),
                rs.getString("audience"),
                Set.of((String[]) rs.getArray("scopes").getArray()),
                rs.getString("claims"),
                rs.getTimestamp("issued_at").toInstant(),
                rs.getTimestamp("expires_at").toInstant(),
                revokedAt == null ? null : revokedAt.toInstant());
    }
}
