package dev.aib.broker;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AdminApiIT extends IntegrationTestBase {

    @Test
    void adminEndpointsRequireTheAdminToken() {
        Map<String, Object> body = Map.of("name", "x");

        assertThat(postJson("/admin/agents", body, null).status()).isEqualTo(401);
        assertThat(postJson("/admin/agents", body, "wrong-token").status()).isEqualTo(401);
        assertThat(postJson("/delegations", body, null).status()).isEqualTo(401);
    }

    @Test
    void registersAnAgentWithItsPublicKey() {
        ECKey key = newKey();

        Response response = postJson("/admin/agents", Map.of(
                "name", "support-bot",
                "public_jwk", key.toPublicJWK().toJSONObject(),
                "allowed_audiences", List.of(ORDERS)), ADMIN_TOKEN);

        assertThat(response.status()).isEqualTo(201);
        assertThat(response.string("id")).startsWith("agt_");
        assertThat(response.string("key_id")).isEqualTo(key.getKeyID());
        assertThat(response.json().get("allowed_audiences")).isEqualTo(List.of(ORDERS));
    }

    @Test
    void refusesPrivateKeysAndUnknownAudiences() {
        ECKey key = newKey();

        Response privateKey = postJson("/admin/agents", Map.of(
                "name", "leaky-bot", "public_jwk", key.toJSONObject(), "allowed_audiences", List.of(ORDERS)), ADMIN_TOKEN);
        Response unknownAudience = postJson("/admin/agents", Map.of(
                "name", "bot", "public_jwk", key.toPublicJWK().toJSONObject(),
                "allowed_audiences", List.of("https://payments.example")), ADMIN_TOKEN);

        assertThat(privateKey.status()).isEqualTo(400);
        assertThat(privateKey.string("error_description")).contains("private key material");
        assertThat(unknownAudience.status()).isEqualTo(400);
    }

    @Test
    void delegationTokenIsAudienceBoundToTheBroker() throws Exception {
        TestAgent agent = registerAgent("support-bot");

        Response response = createDelegation(agent, List.of("orders:read"), null);

        assertThat(response.status()).isEqualTo(201);
        SignedJWT token = SignedJWT.parse(response.string("delegation_token"));
        assertThat(token.getHeader().getType().getType()).isEqualTo("dlg+jwt");
        assertThat(token.getJWTClaimsSet().getAudience()).containsExactly(ISSUER);
        assertThat(token.getJWTClaimsSet().getSubject()).isEqualTo("alice");
        assertThat(token.getJWTClaimsSet().getStringClaim("client_id")).isEqualTo(agent.id());
        assertThat(token.getJWTClaimsSet().getStringClaim("delegation_id")).isEqualTo(response.string("delegation_id"));
    }

    @Test
    void delegationsDefaultToOneHourAndAreCappedAtTwentyFourHours() throws Exception {
        TestAgent agent = registerAgent("support-bot");

        Response defaulted = createDelegation(agent, List.of("orders:read"), null);
        Response tooLong = createDelegation(agent, List.of("orders:read"), Duration.ofHours(25).toSeconds());

        Duration lifetime = Duration.between(Instant.now(), Instant.parse(defaulted.string("expires_at")));
        assertThat(lifetime).isBetween(Duration.ofMinutes(59), Duration.ofHours(1));
        assertThat(tooLong.status()).isEqualTo(400);
    }

    @Test
    void delegationScopesMustBeAvailableToTheAgent() {
        TestAgent agent = registerAgent("support-bot");

        assertThat(createDelegation(agent, List.of("billing:read"), null).status()).isEqualTo(400);
        assertThat(createDelegation(agent, List.of(), null).status()).isEqualTo(400);
    }

    @Test
    void disabledAgentsCannotReceiveDelegations() {
        TestAgent agent = registerAgent("support-bot");

        Response disabled = postJson("/admin/agents/" + agent.id() + "/disable", Map.of(), ADMIN_TOKEN);

        assertThat(disabled.status()).isEqualTo(200);
        assertThat(disabled.json().get("disabled_at")).isNotNull();
        assertThat(createDelegation(agent, List.of("orders:read"), null).status()).isEqualTo(409);
    }

    @Test
    void unknownAgentsReturnNotFound() {
        assertThat(postJson("/admin/agents/agt_missing/disable", Map.of(), ADMIN_TOKEN).status()).isEqualTo(404);
    }
}
