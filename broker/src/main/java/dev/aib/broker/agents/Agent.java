package dev.aib.broker.agents;

import com.nimbusds.jose.jwk.ECKey;
import java.time.Instant;
import java.util.List;

public record Agent(
        String id,
        String name,
        ECKey publicKey,
        List<String> allowedAudiences,
        Instant createdAt,
        Instant disabledAt) {

    public boolean isDisabled() {
        return disabledAt != null;
    }
}
