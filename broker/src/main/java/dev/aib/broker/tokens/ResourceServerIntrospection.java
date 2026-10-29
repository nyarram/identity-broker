package dev.aib.broker.tokens;

import dev.aib.broker.config.BrokerProperties;
import dev.aib.broker.config.BrokerProperties.Resource;
import java.util.List;
import java.util.Optional;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;

/**
 * Wraps Spring's introspection so that only resource servers can introspect, and only tokens
 * issued for them. Anyone else, an agent included, is told every token is inactive.
 */
public class ResourceServerIntrospection implements AuthenticationProvider {

    private final AuthenticationProvider delegate;
    private final BrokerProperties properties;

    public ResourceServerIntrospection(AuthenticationProvider delegate, BrokerProperties properties) {
        this.delegate = delegate;
        this.properties = properties;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        OAuth2TokenIntrospectionAuthenticationToken request = (OAuth2TokenIntrospectionAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken client = (OAuth2ClientAuthenticationToken) request.getPrincipal();
        Optional<Resource> resource = client.getRegisteredClient() == null
                ? Optional.empty()
                : properties.resourceForClient(client.getRegisteredClient().getClientId());
        if (resource.isEmpty()) {
            return inactive(request, client);
        }

        OAuth2TokenIntrospectionAuthenticationToken result =
                (OAuth2TokenIntrospectionAuthenticationToken) delegate.authenticate(authentication);
        OAuth2TokenIntrospection claims = result.getTokenClaims();
        List<String> audience = claims.getAudience();
        if (!claims.isActive() || audience == null || !audience.contains(resource.get().id())) {
            return inactive(request, client);
        }
        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return delegate.supports(authentication);
    }

    private static Authentication inactive(OAuth2TokenIntrospectionAuthenticationToken request, Authentication client) {
        return new OAuth2TokenIntrospectionAuthenticationToken(
                request.getToken(), client, OAuth2TokenIntrospection.builder().build());
    }
}
