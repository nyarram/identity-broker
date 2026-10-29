package dev.aib.broker;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

class TokenExchangeIT extends IntegrationTestBase {

    @Autowired
    JdbcClient jdbc;

    @Test
    void exchangesADelegationForANarrowShortLivedAccessToken() throws Exception {
        TestAgent agent = registerAgent("support-bot");
        Response delegation = createDelegation(agent, List.of("orders:read", "orders:refund"), null);
        Map<String, String> form = exchangeForm(agent, delegation.string("delegation_token"), "orders:refund");
        form.put("authorization_details", "[{\"type\":\"refund\",\"order_id\":\"1042\",\"max_amount_cents\":3000}]");

        Response response = postForm("/oauth2/token", form);

        assertThat(response.status()).as(response.toString()).isEqualTo(200);
        assertThat(response.string("token_type")).isEqualTo("Bearer");
        assertThat(response.string("issued_token_type")).isEqualTo("urn:ietf:params:oauth:token-type:access_token");

        SignedJWT token = SignedJWT.parse(response.string("access_token"));
        assertThat(token.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        assertThat(token.getHeader().getType().getType()).isEqualTo("at+jwt");

        JWTClaimsSet claims = token.getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo(ISSUER);
        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.getJSONObjectClaim("act")).containsEntry("sub", agent.id());
        assertThat(claims.getStringClaim("client_id")).isEqualTo(agent.id());
        assertThat(claims.getAudience()).containsExactly(ORDERS);
        assertThat(claims.getStringClaim("scope")).isEqualTo("orders:refund");
        assertThat(claims.getStringClaim("delegation_id")).isEqualTo(delegation.string("delegation_id"));
        assertThat(claims.getJWTID()).isNotBlank();
        assertThat(claims.getListClaim("authorization_details")).hasSize(1);
        long lifetimeSeconds = (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000;
        assertThat(lifetimeSeconds).isPositive().isLessThanOrEqualTo(300);
    }

    @Test
    void accessTokenVerifiesAgainstThePublishedJwks() throws Exception {
        TestAgent agent = registerAgent("support-bot");
        String accessToken = exchange(agent, delegationToken(agent, "orders:read"), "orders:read").string("access_token");

        JWKSet jwks = JWKSet.parse(get("/oauth2/jwks").json());
        SignedJWT token = SignedJWT.parse(accessToken);
        ECKey key = (ECKey) jwks.getKeyByKeyId(token.getHeader().getKeyID());

        assertThat(key).isNotNull();
        assertThat(key.isPrivate()).isFalse();
        assertThat(token.verify(new ECDSAVerifier(key))).isTrue();
    }

    @Test
    void recordsEveryIssuedToken() throws Exception {
        TestAgent agent = registerAgent("support-bot");
        String accessToken = exchange(agent, delegationToken(agent, "orders:read"), "orders:read").string("access_token");
        String jti = SignedJWT.parse(accessToken).getJWTClaimsSet().getJWTID();

        Map<String, Object> row = jdbc.sql("select agent_id, user_id, audience from issued_tokens where jti = :jti")
                .param("jti", jti)
                .query()
                .singleRow();

        assertThat(row).containsEntry("agent_id", agent.id()).containsEntry("user_id", "alice").containsEntry("audience", ORDERS);
    }

    @Test
    void tokenNeverOutlivesAShortDelegation() throws Exception {
        TestAgent agent = registerAgent("support-bot");
        Response delegation = createDelegation(agent, List.of("orders:read"), 60L);

        String accessToken = exchange(agent, delegation.string("delegation_token"), "orders:read").string("access_token");

        JWTClaimsSet claims = SignedJWT.parse(accessToken).getJWTClaimsSet();
        assertThat(claims.getExpirationTime().toInstant()).isBeforeOrEqualTo(
                Instant.parse(delegation.string("expires_at")));
    }

    // ---- Client authentication (private_key_jwt) ----

    @Test
    void rejectsAnAssertionSignedWithAnotherKey() {
        TestAgent agent = registerAgent("support-bot");
        Map<String, String> form = exchangeForm(agent, delegationToken(agent, "orders:read"), "orders:read");
        form.put("client_assertion", clientAssertion(agent.id(), newKey(), ISSUER + "/oauth2/token", Duration.ofMinutes(1)));

        assertError(postForm("/oauth2/token", form), 401, "invalid_client");
    }

    @Test
    void rejectsAnAssertionForAnotherAudienceOrWithALongLifetime() {
        TestAgent agent = registerAgent("support-bot");
        String delegationToken = delegationToken(agent, "orders:read");

        Map<String, String> wrongAudience = exchangeForm(agent, delegationToken, "orders:read");
        wrongAudience.put("client_assertion", clientAssertion(agent.id(), agent.key(), "https://elsewhere.example", Duration.ofMinutes(1)));
        Map<String, String> longLived = exchangeForm(agent, delegationToken, "orders:read");
        longLived.put("client_assertion", clientAssertion(agent.id(), agent.key(), ISSUER + "/oauth2/token", Duration.ofHours(1)));

        assertError(postForm("/oauth2/token", wrongAudience), 401, "invalid_client");
        assertError(postForm("/oauth2/token", longLived), 401, "invalid_client");
    }

    @Test
    void disabledAgentsCannotAuthenticate() {
        TestAgent agent = registerAgent("support-bot");
        String delegationToken = delegationToken(agent, "orders:read");

        postJson("/admin/agents/" + agent.id() + "/disable", Map.of(), ADMIN_TOKEN);

        assertError(exchange(agent, delegationToken, "orders:read"), 401, "invalid_client");
    }

    // ---- Binding the token to the delegation ----

    @Test
    void anAgentCannotUseAnotherAgentsDelegation() {
        TestAgent owner = registerAgent("support-bot");
        TestAgent rogue = registerAgent("rogue-bot");

        assertError(exchange(rogue, delegationToken(owner, "orders:read"), "orders:read"), 400, "invalid_grant");
    }

    @Test
    void scopeMustBeRequestedAndWithinTheDelegation() {
        TestAgent agent = registerAgent("support-bot");
        String delegationToken = delegationToken(agent, "orders:read");

        assertError(exchange(agent, delegationToken, "orders:refund"), 400, "invalid_scope");
        assertError(exchange(agent, delegationToken, "orders:read orders:refund"), 400, "invalid_scope");
        Map<String, String> noScope = exchangeForm(agent, delegationToken, "");
        noScope.remove("scope");
        assertError(postForm("/oauth2/token", noScope), 400, "invalid_scope");
    }

    @Test
    void resourceMustBeOneTheAgentIsRegisteredFor() {
        TestAgent agent = registerAgent("support-bot");
        String delegationToken = delegationToken(agent, "orders:read");

        Map<String, String> otherResource = exchangeForm(agent, delegationToken, "orders:read");
        otherResource.put("resource", "https://payments.example");
        Map<String, String> noResource = exchangeForm(agent, delegationToken, "orders:read");
        noResource.remove("resource");

        assertError(postForm("/oauth2/token", otherResource), 400, "invalid_target");
        assertError(postForm("/oauth2/token", noResource), 400, "invalid_target");
    }

    @Test
    void anAccessTokenCannotBeExchangedForAnother() {
        TestAgent agent = registerAgent("support-bot");
        String accessToken = exchange(agent, delegationToken(agent, "orders:read"), "orders:read").string("access_token");

        assertError(exchange(agent, accessToken, "orders:read"), 400, "invalid_grant");
    }

    @Test
    void expiredDelegationsCannotBeExchanged() {
        TestAgent agent = registerAgent("support-bot");
        Response delegation = createDelegation(agent, List.of("orders:read"), null);
        jdbc.sql("update delegations set expires_at = now() - interval '1 minute' where id = :id")
                .param("id", delegation.string("delegation_id"))
                .update();

        assertError(exchange(agent, delegation.string("delegation_token"), "orders:read"), 400, "invalid_grant");
    }

    @Test
    void unknownOrTamperedSubjectTokensAreRejected() {
        TestAgent agent = registerAgent("support-bot");
        String delegationToken = delegationToken(agent, "orders:read");
        String tampered = delegationToken.substring(0, delegationToken.lastIndexOf('.')) + ".AAAA";

        assertError(exchange(agent, tampered, "orders:read"), 400, "invalid_grant");
    }

    @Test
    void malformedAuthorizationDetailsAreRejected() {
        TestAgent agent = registerAgent("support-bot");
        Map<String, String> form = exchangeForm(agent, delegationToken(agent, "orders:refund"), "orders:refund");
        form.put("authorization_details", "{\"type\":\"refund\"}");

        assertError(postForm("/oauth2/token", form), 400, "invalid_authorization_details");
    }

    private static void assertError(Response response, int status, String error) {
        assertThat(response.status()).as(response.toString()).isEqualTo(status);
        assertThat(response.string("error")).as(response.toString()).isEqualTo(error);
    }
}
