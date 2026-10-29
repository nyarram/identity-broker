package dev.aib.broker.tokens;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.aib.broker.agents.AgentClientRepository;
import dev.aib.broker.audit.AuditLog;
import dev.aib.broker.audit.AuditLog.EventType;
import dev.aib.broker.audit.AuditLog.NewEvent;
import dev.aib.broker.delegations.Delegation;
import dev.aib.broker.delegations.DelegationRepository;
import dev.aib.broker.support.Ids;
import dev.aib.broker.tokens.IssuedTokenRepository.IssuedToken;
import java.security.Principal;
import java.text.ParseException;
import java.time.Clock;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Backs Spring Authorization Server with the broker's own tables instead of its generic
 * oauth2_authorization table. Delegations become subject tokens for token exchange, and
 * every exchanged access token is recorded in issued_tokens.
 */
@Service
public class BrokerAuthorizationService implements OAuth2AuthorizationService {

    /** Attribute holding the {@link Delegation} behind a delegation-token authorization. */
    public static final String DELEGATION_ATTRIBUTE = "aib.delegation";

    static final AuthorizationGrantType DELEGATION_GRANT = new AuthorizationGrantType("urn:aib:delegation");

    private final DelegationRepository delegations;
    private final IssuedTokenRepository issuedTokens;
    private final AgentClientRepository clients;
    private final AuditLog audit;
    private final TransactionTemplate transactions;
    private final Clock clock;

    BrokerAuthorizationService(
            DelegationRepository delegations,
            IssuedTokenRepository issuedTokens,
            AgentClientRepository clients,
            AuditLog audit,
            TransactionTemplate transactions,
            Clock clock) {
        this.delegations = delegations;
        this.issuedTokens = issuedTokens;
        this.clients = clients;
        this.audit = audit;
        this.transactions = transactions;
        this.clock = clock;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2AccessToken> token = authorization.getAccessToken();
        if (DELEGATION_GRANT.equals(authorization.getAuthorizationGrantType())) {
            // The only change ever saved for a delegation is its revocation (RFC 7009)
            if (token.isInvalidated()) {
                delegations.revoke(authorization.getId(), clock.instant());
            }
            return;
        }
        if (!AuthorizationGrantType.TOKEN_EXCHANGE.equals(authorization.getAuthorizationGrantType())) {
            throw new IllegalStateException("Unsupported grant type " + authorization.getAuthorizationGrantType());
        }
        String value = token.getToken().getTokenValue();
        JWTClaimsSet claims = parseClaims(value);
        IssuedToken issued = new IssuedToken(
                claims.getJWTID(),
                (String) claims.getClaim("delegation_id"),
                authorization.getRegisteredClientId(),
                authorization.getPrincipalName(),
                claims.getAudience().getFirst(),
                authorization.getAuthorizedScopes(),
                claims.toString(),
                token.getToken().getIssuedAt(),
                token.getToken().getExpiresAt(),
                token.isInvalidated() ? clock.instant() : null);

        // The token is only returned to the agent if it was recorded and audited
        transactions.executeWithoutResult(status -> {
            issuedTokens.upsert(issued, Ids.sha256(value));
            if (!token.isInvalidated()) {
                audit.append(new NewEvent(EventType.TOKEN_ISSUED, issued.agentId(), issued.userId(),
                        issued.delegationId(), issued.jti(), issuedRequest(claims), "permit",
                        GrantHolder.get().map(ExchangeRules.Grant::policyReason).orElse(null)));
            } else {
                // The agent revoked its own token through /oauth2/revoke (RFC 7009)
                audit.append(new NewEvent(EventType.TOKEN_REVOKED, issued.agentId(), issued.userId(),
                        issued.delegationId(), issued.jti(), Map.of("endpoint", "/oauth2/revoke"), null,
                        "Revoked by the agent"));
            }
        });
    }

    private static Map<String, Object> issuedRequest(JWTClaimsSet claims) {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("resource", claims.getAudience().getFirst());
        request.put("scope", claims.getClaim("scope"));
        request.put("authorization_details", claims.getClaim("authorization_details"));
        request.put("expires_at", claims.getExpirationTime().toInstant().toString());
        return request;
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        throw new UnsupportedOperationException("Tokens are revoked, never deleted, so the record stays auditable");
    }

    /** Not used by token exchange, introspection or revocation, which all look up by token. */
    @Override
    public OAuth2Authorization findById(String id) {
        return null;
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (tokenType != null && !OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            return null;
        }
        String hash = Ids.sha256(token);
        Optional<Delegation> delegation = delegations.findByTokenHash(hash);
        if (delegation.isPresent()) {
            return fromDelegation(delegation.get(), token);
        }
        return issuedTokens.findByTokenHash(hash).map(t -> fromIssuedToken(t, token)).orElse(null);
    }

    private OAuth2Authorization fromDelegation(Delegation d, String tokenValue) {
        if (!d.isActive(clock.instant())) {
            return null; // Expired or revoked delegations are treated as unknown: invalid_grant
        }
        RegisteredClient agent = clients.findAgent(d.agentId());
        if (agent == null) {
            return null; // Agent unknown or disabled, so its delegations are unusable
        }
        OAuth2AccessToken token = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, tokenValue, d.createdAt(), d.expiresAt(), d.scopes());
        return OAuth2Authorization.withRegisteredClient(agent)
                .id(d.id())
                .principalName(d.userId())
                .authorizationGrantType(DELEGATION_GRANT)
                .authorizedScopes(d.scopes())
                .attribute(Principal.class.getName(), userPrincipal(d.userId()))
                .attribute(DELEGATION_ATTRIBUTE, d)
                .token(token, metadata -> {
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claimsMap(parseClaims(tokenValue)));
                    metadata.put(OAuth2TokenFormat.class.getName(), OAuth2TokenFormat.SELF_CONTAINED.getValue());
                })
                .build();
    }

    /** Unknown, i.e. inactive, once its agent is disabled; invalidated once it or its delegation is revoked. */
    private OAuth2Authorization fromIssuedToken(IssuedToken t, String tokenValue) {
        RegisteredClient agent = clients.findAgent(t.agentId());
        if (agent == null) {
            return null;
        }
        boolean delegationRevoked = delegations.findById(t.delegationId())
                .map(d -> d.revokedAt() != null)
                .orElse(true);
        OAuth2AccessToken token = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, tokenValue, t.issuedAt(), t.expiresAt(), t.scopes());
        return OAuth2Authorization.withRegisteredClient(agent)
                .id(t.jti())
                .principalName(t.userId())
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .authorizedScopes(t.scopes())
                .attribute(Principal.class.getName(), userPrincipal(t.userId()))
                .token(token, metadata -> {
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claimsMap(parseStoredClaims(t.claimsJson())));
                    metadata.put(OAuth2TokenFormat.class.getName(), OAuth2TokenFormat.SELF_CONTAINED.getValue());
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                            t.revokedAt() != null || delegationRevoked);
                })
                .build();
    }

    private static UsernamePasswordAuthenticationToken userPrincipal(String userId) {
        return new UsernamePasswordAuthenticationToken(userId, null, List.of());
    }

    // Safe without verifying the signature: the token was found by the hash of its exact value
    private static JWTClaimsSet parseClaims(String jwt) {
        try {
            return SignedJWT.parse(jwt).getJWTClaimsSet();
        } catch (ParseException e) {
            throw new IllegalStateException("Stored token is not a JWT", e);
        }
    }

    private static JWTClaimsSet parseStoredClaims(String json) {
        try {
            return JWTClaimsSet.parse(json);
        } catch (ParseException e) {
            throw new IllegalStateException("Stored token claims are not valid JSON", e);
        }
    }

    /** Spring expects exp, iat and nbf as Instants in token metadata; Nimbus gives Dates. */
    private static Map<String, Object> claimsMap(JWTClaimsSet claims) {
        Map<String, Object> map = new LinkedHashMap<>(claims.getClaims());
        map.replaceAll((name, value) -> value instanceof Date date ? date.toInstant() : value);
        return map;
    }
}
