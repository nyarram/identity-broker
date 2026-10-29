package dev.aib.broker.tokens;

import com.fasterxml.jackson.annotation.JsonProperty;
import dev.aib.broker.audit.AuditLog;
import dev.aib.broker.audit.AuditLog.EventType;
import dev.aib.broker.audit.AuditLog.NewEvent;
import dev.aib.broker.support.ApiException;
import dev.aib.broker.tokens.IssuedTokenRepository.IssuedToken;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/** Revokes a single access token by its jti. */
@RestController
class TokenAdminController {

    record RevokedResponse(String jti, @JsonProperty("revoked_at") Instant revokedAt) {}

    private final IssuedTokenRepository issuedTokens;
    private final AuditLog audit;
    private final Clock clock;

    TokenAdminController(IssuedTokenRepository issuedTokens, AuditLog audit, Clock clock) {
        this.issuedTokens = issuedTokens;
        this.audit = audit;
        this.clock = clock;
    }

    @PostMapping("/admin/tokens/{jti}/revoke")
    @Transactional
    RevokedResponse revoke(@PathVariable String jti) {
        IssuedToken token = issuedTokens.findByJti(jti).orElseThrow(() -> ApiException.notFound("No token " + jti));
        if (issuedTokens.revoke(jti, clock.instant())) {
            audit.append(new NewEvent(EventType.TOKEN_REVOKED, token.agentId(), token.userId(), token.delegationId(),
                    jti, Map.of(), null, "Revoked by admin"));
        }
        return new RevokedResponse(jti, issuedTokens.findByJti(jti).orElseThrow().revokedAt());
    }
}
