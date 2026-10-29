package dev.aib.broker.tokens;

import dev.aib.broker.agents.AgentClientRepository;
import dev.aib.broker.delegations.Delegation;
import dev.aib.broker.tokens.ExchangeRules.Grant;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

/**
 * Shapes exchanged access tokens into the RFC 9068 profile in the spec: the human as
 * {@code sub}, the agent as {@code act.sub} and {@code client_id}, one audience, and
 * only the scopes the delegation allows.
 */
@Component
class AccessTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    static final String ACCESS_TOKEN_TYPE = "at+jwt";

    private final ExchangeRules rules;
    private final Clock clock;

    AccessTokenCustomizer(ExchangeRules rules, Clock clock) {
        this.rules = rules;
        this.clock = clock;
    }

    @Override
    public void customize(JwtEncodingContext context) {
        context.getJwsHeader().algorithm(SignatureAlgorithm.ES256);
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
                || !AuthorizationGrantType.TOKEN_EXCHANGE.equals(context.getAuthorizationGrantType())) {
            return;
        }

        OAuth2Authorization subject = context.getAuthorization();
        Delegation delegation = subject == null ? null : subject.getAttribute(BrokerAuthorizationService.DELEGATION_ATTRIBUTE);
        if (delegation == null) {
            // Stops an agent from exchanging an access token for another one
            throw error("invalid_grant", "subject_token must be a delegation token");
        }

        OAuth2TokenExchangeAuthenticationToken request = context.getAuthorizationGrant();
        List<String> agentAudiences =
                context.getRegisteredClient().getClientSettings().getSetting(AgentClientRepository.ALLOWED_AUDIENCES);
        Object details = request.getAdditionalParameters().get("authorization_details");

        Grant grant;
        try {
            grant = rules.evaluate(
                    new ExchangeRules.Request(
                            context.getRegisteredClient().getClientId(),
                            request.getScopes(),
                            request.getResources(),
                            request.getAudiences(),
                            details == null ? null : details.toString()),
                    delegation,
                    agentAudiences,
                    clock.instant(),
                    context.getClaims().build().getExpiresAt());
        } catch (ExchangeRules.Denied denied) {
            throw error(denied.code(), denied.getMessage());
        }

        context.getJwsHeader().type(ACCESS_TOKEN_TYPE);
        context.getClaims()
                .audience(List.of(grant.audience()))
                .expiresAt(grant.expiresAt())
                .claim("scope", String.join(" ", grant.scopes()))
                .claim("client_id", delegation.agentId())
                .claim("act", Map.of("sub", delegation.agentId()))
                .claim("delegation_id", delegation.id());
        if (!grant.authorizationDetails().isEmpty()) {
            context.getClaims().claim("authorization_details", grant.authorizationDetails());
        }
    }

    private static OAuth2AuthenticationException error(String code, String description) {
        return new OAuth2AuthenticationException(new OAuth2Error(code, description, null));
    }
}
