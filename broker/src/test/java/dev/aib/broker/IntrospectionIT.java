package dev.aib.broker;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jwt.SignedJWT;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Token introspection (RFC 7662) as the Orders API uses it, and the three levels of revocation. */
class IntrospectionIT extends IntegrationTestBase {

    static final String ORDERS_CLIENT = "orders-api:orders-api-dev-secret";

    @Test
    void aFreshAccessTokenIsActive() {
        TestAgent agent = registerAgent("support-bot");
        String token = accessToken(agent);

        Response result = introspect(token, ORDERS_CLIENT);

        assertThat(result.status()).isEqualTo(200);
        assertThat(result.json()).containsEntry("active", true).containsEntry("sub", "alice");
        assertThat(result.json().get("aud")).isEqualTo(List.of(ORDERS));
    }

    @Test
    void revokingTheTokenMakesItInactive() throws Exception {
        TestAgent agent = registerAgent("support-bot");
        String token = accessToken(agent);
        String jti = SignedJWT.parse(token).getJWTClaimsSet().getJWTID();

        Response revoked = postJson("/admin/tokens/" + jti + "/revoke", Map.of(), ADMIN_TOKEN);

        assertThat(revoked.status()).isEqualTo(200);
        assertThat(introspect(token, ORDERS_CLIENT).json()).containsEntry("active", false);
    }

    @Test
    void revokingTheDelegationMakesItsTokensInactiveAndStopsNewOnes() {
        TestAgent agent = registerAgent("support-bot");
        Response delegation = createDelegation(agent, List.of("orders:read"), null);
        String token = exchangeRead(agent, delegation.string("delegation_token")).string("access_token");

        postJson("/admin/delegations/" + delegation.string("delegation_id") + "/revoke", Map.of(), ADMIN_TOKEN);

        assertThat(introspect(token, ORDERS_CLIENT).json()).containsEntry("active", false);
        assertThat(exchangeRead(agent, delegation.string("delegation_token")).string("error")).isEqualTo("invalid_grant");
    }

    @Test
    void disablingTheAgentMakesAllItsTokensInactive() {
        TestAgent agent = registerAgent("support-bot");
        String token = accessToken(agent);

        postJson("/admin/agents/" + agent.id() + "/disable", Map.of(), ADMIN_TOKEN);

        assertThat(introspect(token, ORDERS_CLIENT).json()).containsEntry("active", false);
    }

    @Test
    void wrongResourceServerCredentialsAreRejected() {
        TestAgent agent = registerAgent("support-bot");

        assertThat(introspect(accessToken(agent), "orders-api:wrong-secret").status()).isEqualTo(401);
    }

    @Test
    void agentsCannotIntrospect() {
        TestAgent agent = registerAgent("support-bot");
        String token = accessToken(agent);
        Map<String, String> form = new LinkedHashMap<>();
        form.put("token", token);
        form.put("client_id", agent.id());
        form.put("client_assertion_type", JWT_BEARER);
        form.put("client_assertion", clientAssertion(agent.id(), agent.key(), ISSUER, Duration.ofMinutes(1)));

        Response result = postForm("/oauth2/introspect", form);

        assertThat(result.json()).containsEntry("active", false);
    }

    @Test
    void delegationTokensAreNotActiveForAResourceServer() {
        TestAgent agent = registerAgent("support-bot");

        assertThat(introspect(delegationToken(agent, "orders:read"), ORDERS_CLIENT).json()).containsEntry("active", false);
    }

    @Test
    void resourceServersCannotObtainTokens() {
        Response result = postForm("/oauth2/token", Map.of("grant_type", "client_credentials"), ORDERS_CLIENT);

        assertThat(result.string("error")).isEqualTo("unauthorized_client");
    }

    @Test
    void revocationsAreAudited() throws Exception {
        TestAgent agent = registerAgent("support-bot");
        String jti = SignedJWT.parse(accessToken(agent)).getJWTClaimsSet().getJWTID();

        postJson("/admin/tokens/" + jti + "/revoke", Map.of(), ADMIN_TOKEN);

        Long count = ownerJdbc().sql("select count(*) from audit_events where event_type = 'token_revoked' and jti = :jti")
                .param("jti", jti).query(Long.class).single();
        assertThat(count).isEqualTo(1);
    }

    private String accessToken(TestAgent agent) {
        return exchangeRead(agent, delegationToken(agent, "orders:read")).string("access_token");
    }

    private Response introspect(String token, String basicAuth) {
        return postForm("/oauth2/introspect", Map.of("token", token), basicAuth);
    }
}
