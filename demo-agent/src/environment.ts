/** Talks to the running stack on behalf of the demo: the admin API, and the Orders API's demo key. */

export interface Environment {
  brokerUrl: string;
  ordersUrl: string;
  adminToken: string;
  demoKey: string;
  resource: string;
}

export function loadEnvironment(): Environment {
  return {
    brokerUrl: process.env.BROKER_URL ?? "http://localhost:9000",
    ordersUrl: process.env.ORDERS_URL ?? "http://localhost:8081",
    adminToken: process.env.BROKER_ADMIN_TOKEN ?? "dev-admin-token-not-for-production",
    demoKey: process.env.ORDERS_DEMO_API_KEY ?? "demo-static-key-not-for-production",
    resource: process.env.ORDERS_API_AUDIENCE ?? "https://orders-api.example",
  };
}

export interface Order {
  id: string;
  customer_id: string;
  description: string;
  total_cents: number;
  refunded_cents: number;
  status: string;
}

export interface AuditEvent {
  seq: number;
  event_type: string;
  decision: string | null;
  reason: string | null;
  delegation_id: string | null;
}

const CUSTOMERS = ["cust_alice", "cust_bob", "cust_carol", "cust_dana"];

export class Stack {
  constructor(readonly env: Environment) {}

  async waitUntilUp(seconds = 60): Promise<void> {
    for (let i = 0; i < seconds; i++) {
      try {
        const broker = await fetch(`${this.env.brokerUrl}/oauth2/jwks`);
        const orders = await fetch(`${this.env.ordersUrl}/orders/1042`);
        if (broker.ok && orders.status === 401) {
          return;
        }
      } catch {
        // not up yet
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    throw new Error(`Broker (${this.env.brokerUrl}) or Orders API (${this.env.ordersUrl}) is not reachable. Run: docker compose up -d --wait`);
  }

  async registerAgent(name: string, publicJwk: JsonWebKey): Promise<string> {
    const agent = (await this.admin("POST", "/admin/agents", {
      name,
      public_jwk: publicJwk,
      allowed_audiences: [this.env.resource],
    })) as { id: string };
    return agent.id;
  }

  async delegate(request: {
    userId: string;
    agentId: string;
    task: string;
    customerId: string;
    orderIds: string[];
    scopes: string[];
  }): Promise<{ delegation_id: string; delegation_token: string }> {
    return (await this.admin("POST", "/delegations", {
      user_id: request.userId,
      agent_id: request.agentId,
      task_description: request.task,
      task_scope: { customer_id: request.customerId, order_ids: request.orderIds },
      scopes: request.scopes,
    })) as { delegation_id: string; delegation_token: string };
  }

  async approve(approvalId: string, decidedBy: string): Promise<void> {
    await this.admin("POST", `/admin/approvals/${approvalId}/approve`, { decided_by: decidedBy });
  }

  async auditEvents(delegationId: string): Promise<AuditEvent[]> {
    const events: AuditEvent[] = [];
    for (let after: number | null = 0; after !== null; ) {
      const page = (await this.admin("GET", `/admin/audit?limit=500&after=${after}`)) as {
        events: AuditEvent[];
        next_after: number | null;
      };
      events.push(...page.events);
      after = page.next_after;
    }
    return events.filter((e) => e.delegation_id === delegationId);
  }

  async verifyAudit(): Promise<{ valid: boolean; events_checked: number }> {
    return (await this.admin("GET", "/admin/audit/verify")) as { valid: boolean; events_checked: number };
  }

  /** Puts the mock orders back as seeded. Needs the Orders API's demo key. */
  async resetOrders(): Promise<void> {
    const response = await fetch(`${this.env.ordersUrl}/admin/reset`, {
      method: "POST",
      headers: { Authorization: `ApiKey ${this.env.demoKey}` },
    });
    if (!response.ok) {
      throw new Error(`Could not reset orders (${response.status}). Is ORDERS_DEMO_API_KEY the same here and in Compose?`);
    }
  }

  /** Every order, read with the demo key, to show what an agent actually changed. */
  async orders(): Promise<Map<string, Order>> {
    const all = new Map<string, Order>();
    for (const customer of CUSTOMERS) {
      const response = await fetch(`${this.env.ordersUrl}/orders?customer=${customer}`, {
        headers: { Authorization: `ApiKey ${this.env.demoKey}` },
      });
      for (const order of (await response.json()) as Order[]) {
        all.set(order.id, order);
      }
    }
    return all;
  }

  private async admin(method: string, path: string, body?: object): Promise<unknown> {
    const response = await fetch(`${this.env.brokerUrl}${path}`, {
      method,
      headers: { Authorization: `Bearer ${this.env.adminToken}`, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
    const json = await response.json();
    if (!response.ok) {
      throw new Error(`Broker ${method} ${path} failed: ${response.status} ${JSON.stringify(json)}`);
    }
    return json;
  }
}

/** What changed between two snapshots of the orders. */
export function changes(before: Map<string, Order>, after: Map<string, Order>) {
  const refunded: Array<{ id: string; cents: number }> = [];
  const deleted: string[] = [];
  const cancelled: string[] = [];
  for (const [id, old] of before) {
    const now = after.get(id);
    if (!now) {
      deleted.push(id);
      continue;
    }
    if (now.refunded_cents > old.refunded_cents) {
      refunded.push({ id, cents: now.refunded_cents - old.refunded_cents });
    }
    if (now.status === "CANCELLED" && old.status !== "CANCELLED") {
      cancelled.push(id);
    }
  }
  return { refunded, deleted, cancelled };
}
