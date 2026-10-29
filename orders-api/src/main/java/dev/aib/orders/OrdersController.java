package dev.aib.orders;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Scope checks happen in {@link SecurityConfig}. M2 adds authorization_details checks on
 * refunds; M3 adds introspection before every write.
 */
@RestController
@RequestMapping("/orders")
class OrdersController {

    private static final Logger log = LoggerFactory.getLogger(OrdersController.class);

    record RefundRequest(@JsonProperty("amount_cents") Long amountCents) {}

    /** Who did it: the human the token is for, and the agent acting for them. */
    record PerformedBy(String user, String agent) {
        static PerformedBy of(Jwt jwt) {
            Map<String, Object> act = jwt.getClaimAsMap("act");
            return new PerformedBy(jwt.getSubject(), act == null ? null : (String) act.get("sub"));
        }
    }

    record WriteResult(Order order, @JsonProperty("performed_by") PerformedBy performedBy) {}

    private final OrderStore orders;

    OrdersController(OrderStore orders) {
        this.orders = orders;
    }

    @GetMapping("/{id}")
    Order get(@PathVariable String id) {
        return orders.find(id).orElseThrow(() -> notFound(id));
    }

    @GetMapping
    List<Order> list(@RequestParam String customer) {
        return orders.findByCustomer(customer);
    }

    @PostMapping("/{id}/refund")
    WriteResult refund(@PathVariable String id, @RequestBody RefundRequest request, @AuthenticationPrincipal Jwt jwt) {
        Order order = get(id);
        Long amount = request.amountCents();
        if (amount == null || amount <= 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "amount_cents must be positive");
        }
        if (amount > order.refundableCents()) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_CONTENT, "Refund exceeds the refundable amount");
        }
        Order updated = orders.update(id, o -> o.withRefund(amount)).orElseThrow(() -> notFound(id));
        return audit("refund " + amount + " cents", updated, jwt);
    }

    @PostMapping("/{id}/cancel")
    WriteResult cancel(@PathVariable String id, @AuthenticationPrincipal Jwt jwt) {
        if (get(id).status() == Order.Status.CANCELLED) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Order is already cancelled");
        }
        Order updated = orders.update(id, Order::cancelled).orElseThrow(() -> notFound(id));
        return audit("cancel", updated, jwt);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void delete(@PathVariable String id, @AuthenticationPrincipal Jwt jwt) {
        if (!orders.delete(id)) {
            throw notFound(id);
        }
        log.info("delete order {} by agent {} for user {}", id, PerformedBy.of(jwt).agent(), jwt.getSubject());
    }

    private static WriteResult audit(String action, Order order, Jwt jwt) {
        PerformedBy by = PerformedBy.of(jwt);
        log.info("{} on order {} by agent {} for user {} (jti {})", action, order.id(), by.agent(), by.user(), jwt.getId());
        return new WriteResult(order, by);
    }

    private static ResponseStatusException notFound(String id) {
        return new ResponseStatusException(HttpStatus.NOT_FOUND, "No order " + id);
    }
}
