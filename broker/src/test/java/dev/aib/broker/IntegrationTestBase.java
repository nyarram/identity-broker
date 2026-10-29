package dev.aib.broker;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.testcontainers.postgresql.PostgreSQLContainer;

/** Runs the broker on a random port against a real Postgres, and talks to it over HTTP. */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "broker.issuer=" + IntegrationTestBase.ISSUER,
            "broker.admin-token=" + IntegrationTestBase.ADMIN_TOKEN
        })
@Import(IntegrationTestBase.Containers.class)
public abstract class IntegrationTestBase {

    public static final String ISSUER = "http://broker.test";
    public static final String ADMIN_TOKEN = "test-admin-token-0123456789abcdef";
    public static final String ORDERS = "https://orders-api.example";

    static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    static final String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
    static final String JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    @TestConfiguration(proxyBeanMethods = false)
    static class Containers {
        @Bean
        @ServiceConnection
        PostgreSQLContainer postgres() {
            return new PostgreSQLContainer("postgres:16-alpine");
        }
    }

    public record Response(int status, Map<String, Object> json) {
        public String string(String key) {
            return (String) json.get(key);
        }
    }

    /** An agent as the tests see it: its id plus the private key only it should hold. */
    public record TestAgent(String id, ECKey key) {}

    @LocalServerPort
    int port;

    final HttpClient http = HttpClient.newHttpClient();

    // ---- HTTP ----

    protected Response get(String path) {
        return send(HttpRequest.newBuilder(uri(path)).GET());
    }

    protected Response postJson(String path, Map<String, Object> body, String bearer) {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri(path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSONObjectUtils.toJSONString(body)));
        if (bearer != null) {
            request.header("Authorization", "Bearer " + bearer);
        }
        return send(request);
    }

    protected Response postForm(String path, Map<String, String> form) {
        String body = form.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        return send(HttpRequest.newBuilder(uri(path))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body)));
    }

    private URI uri(String path) {
        return URI.create("http://localhost:" + port + path);
    }

    private Response send(HttpRequest.Builder request) {
        try {
            HttpResponse<String> response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
            String body = response.body();
            Map<String, Object> json = body == null || body.isBlank() || !body.startsWith("{")
                    ? Map.of()
                    : JSONObjectUtils.parse(body);
            return new Response(response.statusCode(), json);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ---- Broker operations ----

    protected TestAgent registerAgent(String name) {
        ECKey key = newKey();
        Response response = postJson("/admin/agents", Map.of(
                "name", name,
                "public_jwk", key.toPublicJWK().toJSONObject(),
                "allowed_audiences", List.of(ORDERS)), ADMIN_TOKEN);
        if (response.status() != 201) {
            throw new IllegalStateException("Agent registration failed: " + response);
        }
        return new TestAgent(response.string("id"), key);
    }

    protected Response createDelegation(TestAgent agent, List<String> scopes, Long expiresIn) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("user_id", "alice");
        body.put("agent_id", agent.id());
        body.put("task_description", "Help Alice with her running shoes order");
        body.put("task_scope", Map.of("customer_id", "cust_alice", "order_ids", List.of("1042")));
        body.put("scopes", scopes);
        if (expiresIn != null) {
            body.put("expires_in", expiresIn);
        }
        return postJson("/delegations", body, ADMIN_TOKEN);
    }

    protected String delegationToken(TestAgent agent, String... scopes) {
        Response response = createDelegation(agent, List.of(scopes), null);
        if (response.status() != 201) {
            throw new IllegalStateException("Delegation failed: " + response);
        }
        return response.string("delegation_token");
    }

    /** The full set of token exchange parameters; tests override individual entries. */
    protected Map<String, String> exchangeForm(TestAgent agent, String subjectToken, String scope) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", TOKEN_EXCHANGE);
        form.put("client_id", agent.id());
        form.put("client_assertion_type", JWT_BEARER);
        form.put("client_assertion", clientAssertion(agent.id(), agent.key(), ISSUER + "/oauth2/token", Duration.ofMinutes(1)));
        form.put("subject_token", subjectToken);
        form.put("subject_token_type", JWT_TOKEN_TYPE);
        form.put("resource", ORDERS);
        form.put("scope", scope);
        return form;
    }

    protected Response exchange(TestAgent agent, String subjectToken, String scope) {
        return postForm("/oauth2/token", exchangeForm(agent, subjectToken, scope));
    }

    // ---- Keys and assertions ----

    protected static ECKey newKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /** An RFC 7523 client assertion, as the agent SDK will build it. */
    protected static String clientAssertion(String agentId, ECKey signingKey, String audience, Duration lifetime) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(agentId)
                    .subject(agentId)
                    .audience(audience)
                    .jwtID(UUID.randomUUID().toString())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(lifetime)))
                    .build();
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(signingKey.getKeyID()).build(), claims);
            jwt.sign(new ECDSASigner(signingKey));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }
}
