package dev.aib.orders;

import com.fasterxml.jackson.annotation.JsonProperty;
import dev.aib.orders.AccessCheck.PerformedBy;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
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
 * Scope checks happen in {@link SecurityConfig}; {@link AccessCheck} then checks the token's
 * authorization_details and, before writes, asks the broker whether the token is still active.
 */
@RestController
@RequestMapping("/orders")
class OrdersController {

    private static final Logger log = LoggerFactory.getLogger(OrdersController.class);

    record RefundRequest(@JsonProperty("amount_cents") Long amountCents) {}

    record WriteResult(Order order, @JsonProperty("performed_by") PerformedBy performedBy) {}

    private final OrderStore orders;
    private final AccessCheck access;

    OrdersController(OrderStore orders, AccessCheck access) {
        this.orders = orders;
        this.access = access;
    }

    // Each handler checks access before looking the order up, so a token for one order
    // cannot even learn whether another order exists.

    @GetMapping("/{id}")
    Order get(@PathVariable String id, Authentication caller) {
        access.read(caller, id);
        return find(id);
    }

    @GetMapping
    List<Order> list(@RequestParam String customer, Authentication caller) {
        access.list(caller, customer);
        return orders.findByCustomer(customer);
    }

    @PostMapping("/{id}/refund")
    WriteResult refund(@PathVariable String id, @RequestBody RefundRequest request, Authentication caller) {
        Long amount = request.amountCents();
        if (amount == null || amount <= 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "amount_cents must be positive");
        }
        access.refund(caller, id, amount);
        Order order = find(id);
        if (amount > order.refundableCents()) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_CONTENT, "Refund exceeds the refundable amount");
        }
        Order updated = orders.update(id, o -> o.withRefund(amount)).orElseThrow(() -> notFound(id));
        return logged("refund " + amount + " cents", updated, caller);
    }

    @PostMapping("/{id}/cancel")
    WriteResult cancel(@PathVariable String id, Authentication caller) {
        access.write(caller, "cancel", id);
        if (find(id).status() == Order.Status.CANCELLED) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Order is already cancelled");
        }
        Order updated = orders.update(id, Order::cancelled).orElseThrow(() -> notFound(id));
        return logged("cancel", updated, caller);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void delete(@PathVariable String id, Authentication caller) {
        access.write(caller, "delete", id);
        Order order = find(id);
        orders.delete(id);
        logged("delete", order, caller);
    }

    private Order find(String id) {
        return orders.find(id).orElseThrow(() -> notFound(id));
    }

    private WriteResult logged(String action, Order order, Authentication caller) {
        PerformedBy by = access.performedBy(caller);
        log.info("{} on order {} by agent {} for user {}", action, order.id(), by.agent(), by.user());
        return new WriteResult(order, by);
    }

    private static ResponseStatusException notFound(String id) {
        return new ResponseStatusException(HttpStatus.NOT_FOUND, "No order " + id);
    }
}
