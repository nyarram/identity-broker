package dev.aib.orders;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Runs the Orders API with its real JWT decoder and introspection client, pointed at a stub
 * broker that publishes a test key and answers introspection.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OrdersApiSecurityTest {

    static final String ISSUER = "http://broker.test";
    static final String AUDIENCE = "https://orders-api.example";

    static final String DEMO_KEY = "test-demo-key";

    static final ECKey BROKER_KEY = generateKey("broker-key");
    /** Tokens the stub broker reports as inactive, as if revoked. */
    static final Set<String> REVOKED = ConcurrentHashMap.newKeySet();
    static final HttpServer JWKS = startJwksServer(BROKER_KEY);

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        String broker = "http://localhost:" + JWKS.getAddress().getPort();
        registry.add("orders.issuer", () -> ISSUER);
        registry.add("orders.audience", () -> AUDIENCE);
        registry.add("orders.jwk-set-uri", () -> broker + "/oauth2/jwks");
        registry.add("orders.introspection-uri", () -> broker + "/oauth2/introspect");
        registry.add("orders.demo-api-key", () -> DEMO_KEY);
    }

    @AfterAll
    static void stopJwks() {
        JWKS.stop(0);
    }

    @LocalServerPort
    int port;

    final HttpClient http = HttpClient.newHttpClient();

    // ---- Accepted tokens ----

    @Test
    void validTokenWithReadScopeCanReadAnOrder() throws Exception {
        HttpResponse<String> response = call("GET", "/orders/1042", token(c -> {}), null);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("\"id\":\"1042\"").contains("\"customer_id\":\"cust_alice\"");
    }

    @Test
    void writeResponsesRecordTheUserAndTheAgent() throws Exception {
        String token = token(c -> c.claim("scope", "orders:cancel").claim("authorization_details", detail("cancel", "1044")));

        HttpResponse<String> response = call("POST", "/orders/1044/cancel", token, null);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("\"user\":\"alice\"").contains("\"agent\":\"agt_support\"");
    }

    // ---- 401: not a valid access token for this API ----

    @Test
    void missingTokenIs401() throws Exception {
        assertThat(call("GET", "/orders/1042", null, null).statusCode()).isEqualTo(401);
    }

    @Test
    void expiredTokenIs401() throws Exception {
        Instant past = Instant.now().minus(Duration.ofMinutes(10));
        String token = token(c -> c.issueTime(Date.from(past)).expirationTime(Date.from(past.plusSeconds(300))));

        assertThat(call("GET", "/orders/1042", token, null).statusCode()).isEqualTo(401);
    }

    @Test
    void badSignatureIs401() throws Exception {
        // Same key id as the broker's key, different key material
        String forged = sign(header("at+jwt", "broker-key"), validClaims().build(), generateKey("broker-key"));

        assertThat(call("GET", "/orders/1042", forged, null).statusCode()).isEqualTo(401);
    }

    @Test
    void tamperedPayloadIs401() throws Exception {
        String[] parts = token(c -> {}).split("\\.");
        String elevated = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                validClaims().claim("scope", "orders:read orders:delete").build().toString()
                        .getBytes(StandardCharsets.UTF_8));

        assertThat(call("DELETE", "/orders/1042", parts[0] + "." + elevated + "." + parts[2], null).statusCode())
                .isEqualTo(401);
    }

    @Test
    void wrongAudienceIs401() throws Exception {
        String token = token(c -> c.audience("https://billing.example"));

        assertThat(call("GET", "/orders/1042", token, null).statusCode()).isEqualTo(401);
    }

    @Test
    void wrongIssuerIs401() throws Exception {
        String token = token(c -> c.issuer("http://evil.example"));

        assertThat(call("GET", "/orders/1042", token, null).statusCode()).isEqualTo(401);
    }

    @Test
    void delegationTokenIs401() throws Exception {
        // What the broker hands the agent: broker audience, dlg+jwt type
        JWTClaimsSet claims = validClaims().audience(ISSUER).build();
        String delegation = sign(header("dlg+jwt", "broker-key"), claims, BROKER_KEY);
        // Even relabelled as an access token, the audience still rejects it
        String relabelled = sign(header("at+jwt", "broker-key"), claims, BROKER_KEY);

        assertThat(call("GET", "/orders/1042", delegation, null).statusCode()).isEqualTo(401);
        assertThat(call("GET", "/orders/1042", relabelled, null).statusCode()).isEqualTo(401);
    }

    @Test
    void tokenWithoutAccessTokenTypeIs401() throws Exception {
        String plainJwt = sign(header("JWT", "broker-key"), validClaims().build(), BROKER_KEY);

        assertThat(call("GET", "/orders/1042", plainJwt, null).statusCode()).isEqualTo(401);
    }

    @Test
    void tokenMissingClientIdIs401() throws Exception {
        String token = token(c -> c.claim("client_id", null));

        assertThat(call("GET", "/orders/1042", token, null).statusCode()).isEqualTo(401);
    }

    // ---- 403: valid token, wrong scope ----

    @Test
    void missingScopeIs403() throws Exception {
        String readOnly = token(c -> {});

        assertThat(call("POST", "/orders/1042/refund", readOnly, "{\"amount_cents\":3000}").statusCode()).isEqualTo(403);
        assertThat(call("POST", "/orders/1042/cancel", readOnly, null).statusCode()).isEqualTo(403);
        assertThat(call("DELETE", "/orders/1042", readOnly, null).statusCode()).isEqualTo(403);
    }

    @Test
    void refundScopeDoesNotAllowReads() throws Exception {
        String refundOnly = refundToken("1042", 3000);

        assertThat(call("GET", "/orders/1042", refundOnly, null).statusCode()).isEqualTo(403);
        assertThat(call("POST", "/orders/1042/refund", refundOnly, "{\"amount_cents\":3000}").statusCode())
                .isEqualTo(200);
    }

    // ---- 403: valid token and scope, but authorization_details do not cover the request ----

    @Test
    void readTokenForOneOrderCannotReadAnother() throws Exception {
        HttpResponse<String> response = call("GET", "/orders/1043", token(c -> {}), null);

        assertThat(response.statusCode()).isEqualTo(403);
    }

    @Test
    void refundAboveTheTokensMaxAmountIs403() throws Exception {
        String token = refundToken("1045", 3000);

        assertThat(call("POST", "/orders/1045/refund", token, "{\"amount_cents\":3001}").statusCode()).isEqualTo(403);
        assertThat(call("POST", "/orders/1045/refund", token, "{\"amount_cents\":3000}").statusCode()).isEqualTo(200);
    }

    @Test
    void refundForAnotherOrderIs403() throws Exception {
        String token = refundToken("1046", 3000);

        assertThat(call("POST", "/orders/1048/refund", token, "{\"amount_cents\":1000}").statusCode()).isEqualTo(403);
    }

    @Test
    void refundScopeWithoutRefundDetailsIs403() throws Exception {
        // Right scope, but the details describe a read
        String token = token(c -> c.claim("scope", "orders:refund"));

        assertThat(call("POST", "/orders/1042/refund", token, "{\"amount_cents\":100}").statusCode()).isEqualTo(403);
    }

    @Test
    void listingIsLimitedToTheTokensCustomer() throws Exception {
        String token = token(c -> c.claim("authorization_details",
                List.of(Map.of("type", "list", "customer_id", "cust_alice"))));

        assertThat(call("GET", "/orders?customer=cust_alice", token, null).statusCode()).isEqualTo(200);
        assertThat(call("GET", "/orders?customer=cust_bob", token, null).statusCode()).isEqualTo(403);
    }

    @Test
    void tokenWithoutAuthorizationDetailsIs403() throws Exception {
        String token = token(c -> c.claim("authorization_details", null));

        assertThat(call("GET", "/orders/1042", token, null).statusCode()).isEqualTo(403);
    }

    // ---- Error statuses survive Spring's /error dispatch ----

    @Test
    void businessErrorsKeepTheirStatus() throws Exception {
        String token = refundToken("1043", 999999);

        assertThat(call("POST", "/orders/1043/refund", token, "{\"amount_cents\":0}").statusCode()).isEqualTo(400);
        assertThat(call("POST", "/orders/1043/refund", token, "{\"amount_cents\":999999}").statusCode()).isEqualTo(422);
    }

    // ---- Revocation: introspection before writes ----

    @Test
    void aRevokedTokenCannotWrite() throws Exception {
        String token = refundToken("1046", 1000);
        REVOKED.add(token);

        HttpResponse<String> response = call("POST", "/orders/1046/refund", token, "{\"amount_cents\":1000}");

        assertThat(response.statusCode()).isEqualTo(401);
    }

    @Test
    void aRevokedTokenCanStillReadUntilItExpires() throws Exception {
        // Reads are validated locally; the 5-minute lifetime bounds the exposure (see the threat model)
        String token = token(c -> {});
        REVOKED.add(token);

        assertThat(call("GET", "/orders/1042", token, null).statusCode()).isEqualTo(200);
    }

    // ---- The demo's static key: everything is allowed ----

    @Test
    void theStaticDemoKeyCanDoAnything() throws Exception {
        HttpResponse<String> other = callWithKey("GET", "/orders/1050", DEMO_KEY);
        HttpResponse<String> delete = callWithKey("DELETE", "/orders/1059", DEMO_KEY);
        HttpResponse<String> reset = callWithKey("POST", "/admin/reset", DEMO_KEY);

        assertThat(other.statusCode()).isEqualTo(200);
        assertThat(delete.statusCode()).isEqualTo(204);
        assertThat(reset.statusCode()).isEqualTo(204);
        assertThat(callWithKey("GET", "/orders/1059", DEMO_KEY).statusCode()).isEqualTo(200);
    }

    @Test
    void aWrongKeyOrABrokerTokenCannotReset() throws Exception {
        assertThat(callWithKey("POST", "/admin/reset", "wrong-key").statusCode()).isEqualTo(401);
        assertThat(call("POST", "/admin/reset", token(c -> {}), null).statusCode()).isEqualTo(403);
    }

    // ---- Helpers ----

    HttpResponse<String> callWithKey(String method, String path, String key) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .method(method, HttpRequest.BodyPublishers.noBody())
                .header("Authorization", "ApiKey " + key)
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    static List<Map<String, Object>> detail(String type, String orderId) {
        return List.of(Map.of("type", type, "order_id", orderId));
    }

    static String refundToken(String orderId, long maxAmountCents) {
        return token(c -> c.claim("scope", "orders:refund").claim("authorization_details",
                List.of(Map.of("type", "refund", "order_id", orderId, "max_amount_cents", maxAmountCents))));
    }

    static JWTClaimsSet.Builder validClaims() {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("alice")
                .audience(AUDIENCE)
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .jwtID(UUID.randomUUID().toString())
                .claim("client_id", "agt_support")
                .claim("act", Map.of("sub", "agt_support"))
                .claim("scope", "orders:read")
                .claim("delegation_id", "dlg_test")
                .claim("authorization_details", List.of(Map.of("type", "read", "order_id", "1042")));
    }

    static String token(Consumer<JWTClaimsSet.Builder> customize) {
        JWTClaimsSet.Builder claims = validClaims();
        customize.accept(claims);
        return sign(header("at+jwt", "broker-key"), claims.build(), BROKER_KEY);
    }

    static JWSHeader header(String type, String keyId) {
        return new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(type)).keyID(keyId).build();
    }

    static String sign(JWSHeader header, JWTClaimsSet claims, ECKey key) {
        try {
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    HttpResponse<String> call(String method, String path, String token, String jsonBody) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .method(method, jsonBody == null
                        ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(jsonBody))
                .header("Content-Type", "application/json");
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    static ECKey generateKey(String keyId) {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(keyId).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static HttpServer startJwksServer(ECKey key) {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            byte[] body = new JWKSet(key.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
            server.createContext("/oauth2/jwks", exchange -> {
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
            });
            server.createContext("/oauth2/introspect", exchange -> {
                String form = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String token = java.net.URLDecoder.decode(form.replaceFirst("^.*token=([^&]*).*$", "$1"), StandardCharsets.UTF_8);
                boolean authenticated = exchange.getRequestHeaders().getFirst("Authorization") != null;
                byte[] response = (authenticated && !REVOKED.contains(token)
                        ? "{\"active\":true,\"sub\":\"alice\"}"
                        : "{\"active\":false}").getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, response.length);
                exchange.getResponseBody().write(response);
                exchange.close();
            });
            server.start();
            return server;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
