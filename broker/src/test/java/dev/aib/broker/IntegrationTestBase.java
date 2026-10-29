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
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;

/** Runs the broker on a random port against a real Postgres, and talks to it over HTTP. */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "broker.issuer=" + IntegrationTestBase.ISSUER,
            "broker.admin-token=" + IntegrationTestBase.ADMIN_TOKEN
        })
public abstract class IntegrationTestBase {

    public static final String ISSUER = "http://broker.test";
    public static final String ADMIN_TOKEN = "test-admin-token-0123456789abcdef";
    public static final String ORDERS = "https://orders-api.example";

    static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    static final String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
    static final String JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    static final String APP_DB_USER = "broker_app";
    static final String APP_DB_PASSWORD = "broker_app_test";

    /** One database for all test classes, started once and removed when the JVM exits. */
    protected static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

    static {
        POSTGRES.start();
    }

    /** As in production: Flyway runs as the owner, the broker as the restricted app role. */
    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", () -> APP_DB_USER);
        registry.add("spring.datasource.password", () -> APP_DB_PASSWORD);
        registry.add("spring.flyway.user", POSTGRES::getUsername);
        registry.add("spring.flyway.password", POSTGRES::getPassword);
    }

    /** A connection as the schema owner, for tests that play an attacker with database access. */
    protected static JdbcClient ownerJdbc() {
        return JdbcClient.create(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
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

    protected Response getAsAdmin(String path) {
        return send(HttpRequest.newBuilder(uri(path)).header("Authorization", "Bearer " + ADMIN_TOKEN).GET());
    }

    /** For endpoints that return a JSON array. */
    protected String getRawAsAdmin(String path) {
        try {
            HttpRequest request = HttpRequest.newBuilder(uri(path)).header("Authorization", "Bearer " + ADMIN_TOKEN).GET().build();
            return http.send(request, HttpResponse.BodyHandlers.ofString()).body();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
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
        return postForm(path, form, null);
    }

    /** Form post with optional HTTP Basic client credentials, as a resource server sends them. */
    protected Response postForm(String path, Map<String, String> form, String basicAuth) {
        String body = form.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        HttpRequest.Builder request = HttpRequest.newBuilder(uri(path))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (basicAuth != null) {
            request.header("Authorization", "Basic " + java.util.Base64.getEncoder()
                    .encodeToString(basicAuth.getBytes(StandardCharsets.UTF_8)));
        }
        return send(request);
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
    protected Map<String, String> exchangeForm(TestAgent agent, String subjectToken, String scope, String details) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", TOKEN_EXCHANGE);
        form.put("client_id", agent.id());
        form.put("client_assertion_type", JWT_BEARER);
        form.put("client_assertion", clientAssertion(agent.id(), agent.key(), ISSUER + "/oauth2/token", Duration.ofMinutes(1)));
        form.put("subject_token", subjectToken);
        form.put("subject_token_type", JWT_TOKEN_TYPE);
        form.put("resource", ORDERS);
        form.put("scope", scope);
        form.put("authorization_details", details);
        return form;
    }

    protected Response exchange(TestAgent agent, String subjectToken, String scope, String details) {
        return postForm("/oauth2/token", exchangeForm(agent, subjectToken, scope, details));
    }

    /** The usual request in tests: read order 1042, the delegation's task order. */
    protected Response exchangeRead(TestAgent agent, String subjectToken) {
        return exchange(agent, subjectToken, "orders:read", read("1042"));
    }

    // ---- authorization_details ----

    protected static String read(String orderId) {
        return "[{\"type\":\"read\",\"order_id\":\"" + orderId + "\"}]";
    }

    protected static String refund(String orderId, long maxAmountCents) {
        return "[{\"type\":\"refund\",\"order_id\":\"" + orderId + "\",\"max_amount_cents\":" + maxAmountCents + "}]";
    }

    protected static String delete(String orderId) {
        return "[{\"type\":\"delete\",\"order_id\":\"" + orderId + "\"}]";
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
