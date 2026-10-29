package dev.aib.broker.config;

import dev.aib.broker.agents.AgentClientRepository;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

/**
 * Every OAuth client the broker knows: resource servers from configuration (they only call
 * introspection) and agents from the database.
 */
@Component
class BrokerClientRepository implements RegisteredClientRepository {

    private final Map<String, RegisteredClient> resourceServers;
    private final AgentClientRepository agents;

    BrokerClientRepository(BrokerProperties properties, AgentClientRepository agents) {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        this.resourceServers = properties.resources().stream()
                .filter(r -> r.clientId() != null && r.clientSecret() != null)
                .map(r -> resourceServerClient(r, encoder))
                .collect(Collectors.toUnmodifiableMap(RegisteredClient::getClientId, Function.identity()));
        this.agents = agents;
    }

    /**
     * A resource server authenticates with a shared secret (stored only as a bcrypt hash).
     * Spring requires a grant type; the broker refuses to issue tokens for anything but token
     * exchange, so in practice this client can only introspect.
     */
    private static RegisteredClient resourceServerClient(BrokerProperties.Resource r, PasswordEncoder encoder) {
        return RegisteredClient.withId(r.clientId())
                .clientId(r.clientId())
                .clientSecret(encoder.encode(r.clientSecret()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        throw new UnsupportedOperationException("Agents are registered through POST /admin/agents");
    }

    @Override
    public RegisteredClient findById(String id) {
        return findByClientId(id);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        RegisteredClient resourceServer = resourceServers.get(clientId);
        return resourceServer != null ? resourceServer : agents.findAgent(clientId);
    }
}
