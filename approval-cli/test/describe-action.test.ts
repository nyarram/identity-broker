import { describe, expect, it } from "vitest";
import { describeAction } from "../src/cli.ts";

describe("describeAction", () => {
  it("says in plain words what approving would allow", () => {
    expect(describeAction({ type: "refund", order_id: "1045", max_amount_cents: 12000 })).toBe("Refund up to $120.00 on order 1045");
    expect(describeAction({ type: "cancel", order_id: "1042" })).toBe("Cancel order 1042");
    expect(describeAction({ type: "list", customer_id: "cust_bob" })).toBe("List all orders of customer cust_bob");
  });
});
