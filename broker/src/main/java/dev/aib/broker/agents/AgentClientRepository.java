package dev.aib.broker.agents;

import dev.aib.broker.config.BrokerProperties;
import java.util.List;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

/**
 * Exposes registered agents to Spring Authorization Server as OAuth clients. Agents can
 * only authenticate with private_key_jwt and only use the token exchange grant.
 */
@Component
public class AgentClientRepository implements RegisteredClientRepository {

    /** Client settings that carry the agent's registration through to the token pipeline. */
    public static final String PUBLIC_JWK = "aib.public-jwk";
    public static final String ALLOWED_AUDIENCES = "aib.allowed-audiences";

    private final AgentRepository agents;
    private final BrokerProperties properties;

    AgentClientRepository(AgentRepository agents, BrokerProperties properties) {
        this.agents = agents;
        this.properties = properties;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        throw new UnsupportedOperationException("Register agents through POST /admin/agents");
    }

    @Override
    public RegisteredClient findById(String id) {
        return findByClientId(id);
    }

    /** Returns null for unknown or disabled agents, which fails client authentication. */
    @Override
    public RegisteredClient findByClientId(String clientId) {
        return agents.findById(clientId).filter(a -> !a.isDisabled()).map(this::toClient).orElse(null);
    }

    private RegisteredClient toClient(Agent agent) {
        return RegisteredClient.withId(agent.id())
                .clientId(agent.id())
                .clientName(agent.name())
                .clientIdIssuedAt(agent.createdAt())
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .scopes(s -> s.addAll(properties.scopesFor(agent.allowedAudiences())))
                .clientSettings(ClientSettings.builder()
                        .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.ES256)
                        .setting(PUBLIC_JWK, agent.publicKey().toJSONString())
                        .setting(ALLOWED_AUDIENCES, List.copyOf(agent.allowedAudiences()))
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(properties.accessTokenTtl())
                        .build())
                .build();
    }
}
