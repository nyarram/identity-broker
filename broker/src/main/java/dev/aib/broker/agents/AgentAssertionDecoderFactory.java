package dev.aib.broker.agents;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import dev.aib.broker.config.BrokerProperties;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

/**
 * Verifies private_key_jwt client assertions (RFC 7523) against the public key stored at
 * registration. Spring's default factory can only fetch keys from a jwks_uri.
 */
@Component
public class AgentAssertionDecoderFactory implements JwtDecoderFactory<RegisteredClient> {

    /** Reject assertions that stay valid for longer than this, so a leaked one ages out fast. */
    static final Duration MAX_ASSERTION_LIFETIME = Duration.ofMinutes(5);

    private final List<String> acceptedAudiences;
    private final Clock clock;

    AgentAssertionDecoderFactory(BrokerProperties properties, Clock clock) {
        this.acceptedAudiences = List.of(properties.issuer(), properties.issuer() + "/oauth2/token");
        this.clock = clock;
    }

    @Override
    public JwtDecoder createDecoder(RegisteredClient client) {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(
                new JWSVerificationKeySelector<>(JWSAlgorithm.ES256, new ImmutableJWKSet<>(new JWKSet(publicKey(client)))));
        // Claims are checked by the Spring validators below
        processor.setJWTClaimsSetVerifier((claims, context) -> {});

        String clientId = client.getClientId();
        NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(),
                new JwtClaimValidator<String>(JwtClaimNames.ISS, clientId::equals),
                new JwtClaimValidator<String>(JwtClaimNames.SUB, clientId::equals),
                new JwtClaimValidator<List<String>>(
                        JwtClaimNames.AUD, aud -> aud != null && aud.stream().anyMatch(acceptedAudiences::contains)),
                new JwtClaimValidator<Instant>(
                        JwtClaimNames.EXP,
                        exp -> exp != null && exp.isBefore(clock.instant().plus(MAX_ASSERTION_LIFETIME)))));
        return decoder;
    }

    private static ECKey publicKey(RegisteredClient client) {
        try {
            return ECKey.parse((String) client.getClientSettings().getSetting(AgentClientRepository.PUBLIC_JWK));
        } catch (ParseException e) {
            throw new IllegalStateException("Agent " + client.getClientId() + " has an invalid stored key", e);
        }
    }
}
