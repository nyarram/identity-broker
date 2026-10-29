package dev.aib.broker.policy;

import java.util.Map;
import java.util.Optional;

/**
 * The one action a token is requested for, parsed from its RFC 9396
 * authorization_details entry, for example
 * {@code {"type":"refund","order_id":"1042","max_amount_cents":3000}}.
 */
public record ActionRequest(Action action, String orderId, String customerId, long amountCents) {

    public enum Action {
        READ("read", "orders:read"),
        LIST("list", "orders:read"),
        REFUND("refund", "orders:refund"),
        CANCEL("cancel", "orders:cancel"),
        DELETE("delete", "orders:delete");

        private final String type;
        private final String scope;

        Action(String type, String scope) {
            this.type = type;
            this.scope = scope;
        }

        /** The authorization_details type and the Cedar action name. */
        public String type() {
            return type;
        }

        /** The OAuth scope the Orders API requires for this action. */
        public String scope() {
            return scope;
        }

        public static Optional<Action> fromType(String type) {
            for (Action a : values()) {
                if (a.type.equals(type)) {
                    return Optional.of(a);
                }
            }
            return Optional.empty();
        }
    }

    /** The authorization_details entry to put in the access token. */
    public Map<String, Object> toAuthorizationDetail() {
        return switch (action) {
            case LIST -> Map.of("type", action.type(), "customer_id", customerId);
            case REFUND -> Map.of("type", action.type(), "order_id", orderId, "max_amount_cents", amountCents);
            default -> Map.of("type", action.type(), "order_id", orderId);
        };
    }

    public String describe() {
        return switch (action) {
            case LIST -> "list orders of customer " + customerId;
            case REFUND -> "refund up to " + amountCents + " cents on order " + orderId;
            default -> action.type() + " order " + orderId;
        };
    }
}
