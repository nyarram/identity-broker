package dev.aib.orders;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Amounts are integer cents throughout, so policy and API never compare floats. */
public record Order(
        String id,
        @JsonProperty("customer_id") String customerId,
        String description,
        @JsonProperty("total_cents") long totalCents,
        @JsonProperty("refunded_cents") long refundedCents,
        Status status,
        @JsonProperty("customer_note") String customerNote) {

    public enum Status { PLACED, SHIPPED, DELIVERED, CANCELLED }

    Order withRefund(long amountCents) {
        return new Order(id, customerId, description, totalCents, refundedCents + amountCents, status, customerNote);
    }

    Order cancelled() {
        return new Order(id, customerId, description, totalCents, refundedCents, Status.CANCELLED, customerNote);
    }

    long refundableCents() {
        return totalCents - refundedCents;
    }
}
