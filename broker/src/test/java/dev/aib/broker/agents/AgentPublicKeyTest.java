package dev.aib.broker.agents;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import dev.aib.broker.support.ApiException;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AgentPublicKeyTest {

    @Test
    void acceptsAPublicP256KeyAndAssignsAKeyId() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).generate();

        ECKey parsed = AgentService.parsePublicKey(key.toPublicJWK().toJSONObject());

        assertThat(parsed.isPrivate()).isFalse();
        assertThat(parsed.getKeyID()).isEqualTo(key.computeThumbprint().toString());
    }

    @Test
    void rejectsPrivateKeyMaterial() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).generate();
        assertRejected(key.toJSONObject(), "private key material");
    }

    @Test
    void rejectsOtherKeyTypesCurvesAndAlgorithms() throws Exception {
        assertRejected(new RSAKeyGenerator(2048).generate().toPublicJWK().toJSONObject(), "EC P-256");
        assertRejected(new ECKeyGenerator(Curve.P_384).generate().toPublicJWK().toJSONObject(), "EC P-256");

        Map<String, Object> wrongAlg = new HashMap<>(new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256).generate().toPublicJWK().toJSONObject());
        wrongAlg.put("alg", "ES384");
        assertRejected(wrongAlg, "alg must be ES256");
    }

    @Test
    void rejectsMissingOrInvalidJwk() {
        assertRejected(null, "public_jwk is required");
        assertRejected(Map.of("kty", "EC"), "not a valid JWK");
    }

    private static void assertRejected(Map<String, Object> jwk, String message) {
        assertThatThrownBy(() -> AgentService.parsePublicKey(jwk))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining(message);
    }
}
