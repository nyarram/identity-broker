package dev.aib.broker.config;

import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("broker")
public record BrokerProperties(
        String issuer,
        String adminToken,
        String signingKeyFile,
        Duration accessTokenTtl,
        String policyDir,
        List<Resource> resources) {

    /** A resource server the broker issues tokens for (an RFC 8707 resource indicator). */
    public record Resource(String id, Set<String> scopes) {}

    static final int MIN_ADMIN_TOKEN_LENGTH = 24;
    static final Duration MAX_ACCESS_TOKEN_TTL = Duration.ofMinutes(5);

    public BrokerProperties {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalStateException("broker.issuer (BROKER_ISSUER) must be set");
        }
        if (adminToken == null || adminToken.length() < MIN_ADMIN_TOKEN_LENGTH) {
            throw new IllegalStateException(
                    "broker.admin-token (BROKER_ADMIN_TOKEN) must be at least " + MIN_ADMIN_TOKEN_LENGTH + " characters");
        }
        if (accessTokenTtl == null || accessTokenTtl.compareTo(MAX_ACCESS_TOKEN_TTL) > 0) {
            throw new IllegalStateException("broker.access-token-ttl must be at most " + MAX_ACCESS_TOKEN_TTL);
        }
        if (policyDir == null || policyDir.isBlank()) {
            throw new IllegalStateException("broker.policy-dir (BROKER_POLICY_DIR) must be set");
        }
        resources = resources == null ? List.of() : List.copyOf(resources);
    }

    public Optional<Resource> resource(String id) {
        return resources.stream().filter(r -> r.id().equals(id)).findFirst();
    }

    public boolean isKnownResource(String id) {
        return resource(id).isPresent();
    }

    /** All scopes an agent could ever hold, given the resources it may call. */
    public Set<String> scopesFor(Collection<String> audiences) {
        Set<String> scopes = new TreeSet<>();
        audiences.forEach(a -> resource(a).ifPresent(r -> scopes.addAll(r.scopes())));
        return scopes;
    }
}
