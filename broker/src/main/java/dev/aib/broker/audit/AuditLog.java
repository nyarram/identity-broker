package dev.aib.broker.audit;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.util.JSONObjectUtils;
import dev.aib.broker.support.CanonicalJson;
import dev.aib.broker.support.Ids;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Tamper-evident log of broker decisions. Each event's hash covers the previous event's
 * hash, so changing or removing any event breaks every link after it. The chain detects
 * edits, not a wholesale rewrite by someone who can recompute every hash (see the threat
 * model).
 */
@Service
public class AuditLog {

    /** prev_hash of the first event. */
    public static final String GENESIS_HASH = "0".repeat(64);

    /** Postgres advisory lock that serializes appends, so concurrent writers cannot fork the chain. */
    private static final long CHAIN_LOCK = 0x41_49_42_41_55_44_49_54L; // "AIBAUDIT"

    public enum EventType {
        AGENT_REGISTERED, AGENT_DISABLED, DELEGATION_CREATED, DELEGATION_REVOKED,
        TOKEN_ISSUED, TOKEN_DENIED, TOKEN_REVOKED,
        APPROVAL_REQUESTED, APPROVED, DENIED_BY_HUMAN;

        public String value() {
            return name().toLowerCase();
        }
    }

    /** What callers record. {@code request} may hold only strings, whole numbers, booleans, maps and lists. */
    public record NewEvent(
            EventType type,
            String agentId,
            String userId,
            String delegationId,
            String jti,
            Map<String, Object> request,
            String decision,
            String reason) {}

    public record AuditEvent(
            long seq,
            @JsonProperty("occurred_at") Instant occurredAt,
            @JsonProperty("event_type") String eventType,
            @JsonProperty("agent_id") String agentId,
            @JsonProperty("user_id") String userId,
            @JsonProperty("delegation_id") String delegationId,
            String jti,
            Map<String, Object> request,
            String decision,
            String reason,
            @JsonProperty("prev_hash") String prevHash,
            String hash) {}

    /** Result of re-checking the whole chain; {@code firstBrokenSeq} is null when valid. */
    public record Verification(boolean valid, long eventsChecked, Long firstBrokenSeq, String problem) {}

    private final JdbcClient jdbc;
    private final TransactionTemplate transactions;
    private final Clock clock;

    AuditLog(JdbcClient jdbc, TransactionTemplate transactions, Clock clock) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.clock = clock;
    }

    /** Appends an event. Joins the caller's transaction if there is one. */
    public AuditEvent append(NewEvent e) {
        return transactions.execute(status -> {
            jdbc.sql("select pg_advisory_xact_lock(:lock)").param("lock", CHAIN_LOCK).query().listOfRows();
            Optional<Map<String, Object>> last = jdbc.sql("select seq, hash from audit_events order by seq desc limit 1")
                    .query()
                    .listOfRows()
                    .stream()
                    .findFirst();
            long seq = last.map(row -> ((Number) row.get("seq")).longValue() + 1).orElse(1L);
            String prevHash = last.map(row -> (String) row.get("hash")).orElse(GENESIS_HASH);
            // Postgres stores microseconds; truncate so the hash recomputes from the stored value
            Instant occurredAt = clock.instant().truncatedTo(ChronoUnit.MICROS);
            Map<String, Object> request = e.request() == null ? Map.of() : e.request();

            AuditEvent unhashed = new AuditEvent(seq, occurredAt, e.type().value(), e.agentId(), e.userId(),
                    e.delegationId(), e.jti(), request, e.decision(), e.reason(), prevHash, null);
            AuditEvent event = withHash(unhashed, hash(unhashed));

            jdbc.sql("""
                    insert into audit_events (seq, occurred_at, event_type, agent_id, user_id, delegation_id, jti,
                                              request, decision, reason, prev_hash, hash)
                    values (:seq, :occurredAt, :type, :agentId, :userId, :delegationId, :jti,
                            cast(:request as jsonb), :decision, :reason, :prevHash, :hash)
                    """)
                    .param("seq", event.seq())
                    .param("occurredAt", Timestamp.from(event.occurredAt()))
                    .param("type", event.eventType())
                    .param("agentId", event.agentId())
                    .param("userId", event.userId())
                    .param("delegationId", event.delegationId())
                    .param("jti", event.jti())
                    .param("request", CanonicalJson.write(event.request()))
                    .param("decision", event.decision())
                    .param("reason", event.reason())
                    .param("prevHash", event.prevHash())
                    .param("hash", event.hash())
                    .update();
            return event;
        });
    }

    public List<AuditEvent> list(long afterSeq, int limit) {
        return jdbc.sql("select * from audit_events where seq > :after order by seq limit :limit")
                .param("after", afterSeq)
                .param("limit", limit)
                .query(AuditLog::map)
                .list();
    }

    /** Recomputes every hash and link in order, and reports the first event that does not check out. */
    public Verification verify() {
        long[] checked = {0};
        String[] previousHash = {GENESIS_HASH};
        Verification[] broken = {null};
        jdbc.sql("select * from audit_events order by seq").query(rs -> {
            if (broken[0] != null) {
                return;
            }
            AuditEvent event = map(rs, 0);
            long expectedSeq = checked[0] + 1;
            if (event.seq() != expectedSeq) {
                broken[0] = new Verification(false, checked[0], expectedSeq, "Event is missing");
            } else if (!event.hash().equals(hash(event))) {
                broken[0] = new Verification(false, checked[0], event.seq(), "Hash does not match the event's contents");
            } else if (!event.prevHash().equals(previousHash[0])) {
                broken[0] = new Verification(false, checked[0], event.seq(), "prev_hash does not match the previous event");
            } else {
                checked[0]++;
                previousHash[0] = event.hash();
            }
        });
        return broken[0] != null ? broken[0] : new Verification(true, checked[0], null, null);
    }

    /** SHA-256 over the previous hash and the RFC 8785 canonical JSON of the event. */
    static String hash(AuditEvent e) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("seq", e.seq());
        fields.put("occurred_at", e.occurredAt().toString());
        fields.put("event_type", e.eventType());
        fields.put("agent_id", e.agentId());
        fields.put("user_id", e.userId());
        fields.put("delegation_id", e.delegationId());
        fields.put("jti", e.jti());
        fields.put("request", e.request());
        fields.put("decision", e.decision());
        fields.put("reason", e.reason());
        return Ids.sha256(e.prevHash() + CanonicalJson.write(fields));
    }

    private static AuditEvent withHash(AuditEvent e, String hash) {
        return new AuditEvent(e.seq(), e.occurredAt(), e.eventType(), e.agentId(), e.userId(), e.delegationId(),
                e.jti(), e.request(), e.decision(), e.reason(), e.prevHash(), hash);
    }

    private static AuditEvent map(ResultSet rs, int row) throws SQLException {
        try {
            return new AuditEvent(
                    rs.getLong("seq"),
                    rs.getTimestamp("occurred_at").toInstant(),
                    rs.getString("event_type"),
                    rs.getString("agent_id"),
                    rs.getString("user_id"),
                    rs.getString("delegation_id"),
                    rs.getString("jti"),
                    JSONObjectUtils.parse(rs.getString("request")),
                    rs.getString("decision"),
                    rs.getString("reason"),
                    rs.getString("prev_hash"),
                    rs.getString("hash"));
        } catch (ParseException e) {
            throw new SQLException("Audit event request is not valid JSON", e);
        }
    }
}
