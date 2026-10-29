package dev.aib.broker.agents;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import dev.aib.broker.config.BrokerProperties;
import dev.aib.broker.support.ApiException;
import dev.aib.broker.support.Ids;
import java.text.ParseException;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class AgentService {

    private final AgentRepository agents;
    private final BrokerProperties properties;
    private final Clock clock;

    AgentService(AgentRepository agents, BrokerProperties properties, Clock clock) {
        this.agents = agents;
        this.properties = properties;
        this.clock = clock;
    }

    public Agent register(String name, Map<String, Object> publicJwk, List<String> allowedAudiences) {
        if (name == null || name.isBlank()) {
            throw ApiException.badRequest("name is required");
        }
        if (allowedAudiences == null || allowedAudiences.isEmpty()) {
            throw ApiException.badRequest("allowed_audiences must list at least one resource");
        }
        for (String audience : allowedAudiences) {
            if (!properties.isKnownResource(audience)) {
                throw ApiException.badRequest("Unknown resource in allowed_audiences: " + audience);
            }
        }
        Agent agent = new Agent(
                Ids.newId("agt"), name, parsePublicKey(publicJwk), List.copyOf(allowedAudiences), clock.instant(), null);
        agents.insert(agent);
        return agent;
    }

    public Agent get(String id) {
        return agents.findById(id).orElseThrow(() -> ApiException.notFound("No agent " + id));
    }

    public void disable(String id) {
        get(id);
        agents.disable(id, clock.instant());
    }

    /** Agents sign client assertions with ES256, so only public P-256 keys are accepted. */
    static ECKey parsePublicKey(Map<String, Object> jwk) {
        if (jwk == null) {
            throw ApiException.badRequest("public_jwk is required");
        }
        JWK parsed;
        try {
            parsed = JWK.parse(jwk);
        } catch (ParseException e) {
            throw ApiException.badRequest("public_jwk is not a valid JWK: " + e.getMessage());
        }
        if (!(parsed instanceof ECKey key) || !Curve.P_256.equals(key.getCurve())) {
            throw ApiException.badRequest("public_jwk must be an EC P-256 key");
        }
        if (key.isPrivate()) {
            throw ApiException.badRequest("public_jwk contains private key material; send only the public key");
        }
        if (key.getAlgorithm() != null && !JWSAlgorithm.ES256.equals(key.getAlgorithm())) {
            throw ApiException.badRequest("public_jwk alg must be ES256");
        }
        if (key.getKeyUse() != null && !KeyUse.SIGNATURE.equals(key.getKeyUse())) {
            throw ApiException.badRequest("public_jwk use must be sig");
        }
        try {
            return key.getKeyID() != null ? key : new ECKey.Builder(key).keyIDFromThumbprint().build();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }
}
