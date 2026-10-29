package dev.aib.orders;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;

/**
 * The one action an access token allows, from its RFC 9396 authorization_details claim.
 * Scopes say which endpoint a token may call; this says which order and how much.
 */
final class TokenGrant {

    private final Map<String, Object> detail;

    private TokenGrant(Map<String, Object> detail) {
        this.detail = detail;
    }

    static TokenGrant of(Jwt jwt) {
        List<Map<String, Object>> details = jwt.getClaim("authorization_details");
        if (details == null || details.size() != 1) {
            throw forbidden("Token must carry exactly one authorization_details entry");
        }
        return new TokenGrant(details.getFirst());
    }

    void requireOrder(String type, String orderId) {
        if (!type.equals(detail.get("type")) || !orderId.equals(detail.get("order_id"))) {
            throw forbidden("Token does not allow " + type + " on order " + orderId);
        }
    }

    void requireCustomerList(String customerId) {
        if (!"list".equals(detail.get("type")) || !Objects.equals(customerId, detail.get("customer_id"))) {
            throw forbidden("Token does not allow listing orders of " + customerId);
        }
    }

    void requireRefund(String orderId, long amountCents) {
        requireOrder("refund", orderId);
        if (!(detail.get("max_amount_cents") instanceof Number max) || amountCents > max.longValue()) {
            throw forbidden("Refund of " + amountCents + " cents exceeds the token's max_amount_cents");
        }
    }

    private static ResponseStatusException forbidden(String reason) {
        return new ResponseStatusException(HttpStatus.FORBIDDEN, reason);
    }
}
