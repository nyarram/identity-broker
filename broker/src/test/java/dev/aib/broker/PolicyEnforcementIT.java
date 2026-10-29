package dev.aib.broker;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jwt.SignedJWT;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The Cedar policies, enforced through the real token endpoint. Task order: 1042, customer cust_alice. */
class PolicyEnforcementIT extends IntegrationTestBase {

    @Test
    void readingATaskOrderIsIssued() throws Exception {
        TestAgent agent = registerAgent("support-bot");

        Response response = exchangeRead(agent, delegationToken(agent, "orders:read"));

        assertThat(response.status()).isEqualTo(200);
        assertThat(SignedJWT.parse(response.string("access_token")).getJWTClaimsSet().getClaim("authorization_details"))
                .isEqualTo(List.of(Map.of("type", "read", "order_id", "1042")));
    }

    @Test
    void readingAnOrderOutsideTheTaskIsDenied() {
        TestAgent agent = registerAgent("support-bot");

        Response response = exchange(agent, delegationToken(agent, "orders:read"), "orders:read", read("1050"));

        assertDenied(response, "No policy permits: read order 1050");
    }

    @Test
    void refundUpToFiftyDollarsOnATaskOrderIsIssued() throws Exception {
        TestAgent agent = registerAgent("support-bot");

        Response response = exchange(agent, delegationToken(agent, "orders:refund"), "orders:refund", refund("1042", 5000));

        assertThat(response.status()).as(response.toString()).isEqualTo(200);
        assertThat(SignedJWT.parse(response.string("access_token")).getJWTClaimsSet().getClaim("authorization_details"))
                .isEqualTo(List.of(Map.of("type", "refund", "order_id", "1042", "max_amount_cents", 5000L)));
    }

    @Test
    void refundAboveFiftyDollarsWaitsForApproval() {
        TestAgent agent = registerAgent("support-bot");

        Response response = exchange(agent, delegationToken(agent, "orders:refund"), "orders:refund", refund("1042", 12000));

        assertThat(response.status()).isEqualTo(400);
        assertThat(response.string("error")).isEqualTo("authorization_pending");
        assertThat(response.string("approval_id")).startsWith("apr_");
    }

    @Test
    void refundOnAnOrderOutsideTheTaskIsDenied() {
        TestAgent agent = registerAgent("support-bot");

        assertDenied(exchange(agent, delegationToken(agent, "orders:refund"), "orders:refund", refund("1047", 1000)),
                "No policy permits");
    }

    @Test
    void deleteIsDeniedEvenWhenTheDelegationListsTheScope() {
        TestAgent agent = registerAgent("support-bot");

        Response response = exchange(agent, delegationToken(agent, "orders:delete"), "orders:delete", delete("1042"));

        assertDenied(response, "Forbidden by never-delete");
    }

    @Test
    void listingIsLimitedToTheTaskCustomer() {
        TestAgent agent = registerAgent("support-bot");
        String delegationToken = delegationToken(agent, "orders:read");

        Response own = exchange(agent, delegationToken, "orders:read", "[{\"type\":\"list\",\"customer_id\":\"cust_alice\"}]");
        Response other = exchange(agent, delegationToken, "orders:read", "[{\"type\":\"list\",\"customer_id\":\"cust_bob\"}]");

        assertThat(own.status()).isEqualTo(200);
        assertDenied(other, "No policy permits: list orders of customer cust_bob");
    }

    @Test
    void authorizationDetailsAreRequired() {
        TestAgent agent = registerAgent("support-bot");
        Map<String, String> form = exchangeForm(agent, delegationToken(agent, "orders:read"), "orders:read", read("1042"));
        form.remove("authorization_details");

        Response response = postForm("/oauth2/token", form);

        assertThat(response.status()).isEqualTo(400);
        assertThat(response.string("error")).isEqualTo("invalid_authorization_details");
    }

    private static void assertDenied(Response response, String reason) {
        assertThat(response.status()).as(response.toString()).isEqualTo(400);
        assertThat(response.string("error")).isEqualTo("access_denied");
        assertThat(response.string("error_description")).contains(reason);
    }
}
