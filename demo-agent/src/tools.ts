import { BrokerError, type Action, type BrokerClient } from "@aib/agent-sdk";
import type { Printer } from "./print.ts";

/** The support agent's tools. The agent decides which to call; the broker decides whether it may. */
export const TOOLS = [
  {
    name: "get_order",
    description: "Look up one order, including the customer's note on it.",
    inputSchema: object({ order_id: { type: "string" } }),
  },
  {
    name: "list_orders",
    description: "List a customer's orders.",
    inputSchema: object({ customer_id: { type: "string" } }),
  },
  {
    name: "refund_order",
    description: "Refund part or all of an order. Amount in cents: $30.00 is 3000.",
    inputSchema: object({ order_id: { type: "string" }, amount_cents: { type: "integer" } }),
  },
  {
    name: "cancel_order",
    description: "Cancel an order.",
    inputSchema: object({ order_id: { type: "string" } }),
  },
  {
    name: "delete_order",
    description: "Delete an order record.",
    inputSchema: object({ order_id: { type: "string" } }),
  },
];

function object(properties: Record<string, { type: string }>) {
  return { type: "object" as const, properties, required: Object.keys(properties), additionalProperties: false };
}

export interface ToolResult {
  content: string;
  isError: boolean;
}

export type ToolExecutor = (name: string, input: Record<string, unknown>) => Promise<ToolResult>;

interface HttpCall {
  method: string;
  path: string;
  body?: object;
}

/** What each tool call does: the HTTP request, and the one action a token must allow for it. */
function plan(name: string, input: Record<string, unknown>): { action: Action; http: HttpCall } {
  const orderId = String(input.order_id ?? "");
  switch (name) {
    case "get_order":
      return { action: { type: "read", order_id: orderId }, http: { method: "GET", path: `/orders/${orderId}` } };
    case "list_orders": {
      const customerId = String(input.customer_id ?? "");
      return {
        action: { type: "list", customer_id: customerId },
        http: { method: "GET", path: `/orders?customer=${encodeURIComponent(customerId)}` },
      };
    }
    case "refund_order": {
      const amount = Number(input.amount_cents);
      return {
        action: { type: "refund", order_id: orderId, max_amount_cents: amount },
        http: { method: "POST", path: `/orders/${orderId}/refund`, body: { amount_cents: amount } },
      };
    }
    case "cancel_order":
      return { action: { type: "cancel", order_id: orderId }, http: { method: "POST", path: `/orders/${orderId}/cancel` } };
    case "delete_order":
      return { action: { type: "delete", order_id: orderId }, http: { method: "DELETE", path: `/orders/${orderId}` } };
    default:
      throw new Error(`Unknown tool ${name}`);
  }
}

async function callOrdersApi(ordersUrl: string, http: HttpCall, authorization: string): Promise<ToolResult> {
  const response = await fetch(`${ordersUrl}${http.path}`, {
    method: http.method,
    headers: { Authorization: authorization, "Content-Type": "application/json" },
    body: http.body ? JSON.stringify(http.body) : undefined,
  });
  const text = await response.text();
  return {
    content: response.ok ? text || `${response.status} OK` : `Orders API returned ${response.status}: ${text}`,
    isError: !response.ok,
  };
}

/**
 * With the broker: every call first gets a token for exactly that action. The agent holds
 * no Orders API credential, only a delegation token that the API itself rejects.
 */
export function brokerTools(options: {
  broker: BrokerClient;
  delegationToken: string;
  ordersUrl: string;
  printer: Printer;
  onApprovalPending: (approvalId: string) => Promise<void>;
}): ToolExecutor {
  return async (name, input) => {
    const { action, http } = plan(name, input);
    let token: string;
    try {
      const issued = await options.broker.getToken({
        delegationToken: options.delegationToken,
        action,
        onApprovalPending: ({ approvalId }) => options.onApprovalPending(approvalId),
      });
      options.printer.tokenIssued(action, issued.expiresAt);
      token = issued.token;
    } catch (error) {
      if (error instanceof BrokerError) {
        options.printer.tokenDenied(error);
        return { content: `The identity broker refused: ${error.code}: ${error.description}`, isError: true };
      }
      throw error;
    }
    const result = await callOrdersApi(options.ordersUrl, http, `Bearer ${token}`);
    options.printer.apiResult(result);
    return result;
  };
}

/** Without the broker: the usual setup, one static key that can do everything. */
export function staticKeyTools(options: { ordersUrl: string; apiKey: string; printer: Printer }): ToolExecutor {
  return async (name, input) => {
    const { http } = plan(name, input);
    const result = await callOrdersApi(options.ordersUrl, http, `ApiKey ${options.apiKey}`);
    options.printer.apiResult(result);
    return result;
  };
}
