import { createPublicKey, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import { BrokerClient, BrokerError, clientAssertion, decodeClaims, generateAgentKey, scopeFor, type Action } from "../src/index.ts";

const BROKER = "http://localhost:9000";
const ISSUER_TOKEN_ENDPOINT = "http://broker:9000/oauth2/token";
const ORDERS = "https://orders-api.example";

/** A fake broker: records requests and answers token requests from a script. */
function fakeBroker(tokenResponses: Array<{ status: number; body: Record<string, unknown> }>, approvalStatuses: string[] = []) {
  const tokenRequests: URLSearchParams[] = [];
  const polls: string[] = [];
  const fetch: typeof globalThis.fetch = async (input, init) => {
    const url = String(input);
    if (url.endsWith("/.well-known/oauth-authorization-server")) {
      return Response.json({ token_endpoint: ISSUER_TOKEN_ENDPOINT });
    }
    if (url.endsWith("/oauth2/token")) {
      tokenRequests.push(new URLSearchParams(String(init?.body)));
      const next = tokenResponses.shift()!;
      return Response.json(next.body, { status: next.status });
    }
    if (url.includes("/approvals/")) {
      polls.push(url);
      return Response.json({ status: approvalStatuses.shift() ?? "pending" });
    }
    throw new Error(`Unexpected request to ${url}`);
  };
  return { fetch, tokenRequests, polls };
}

function jwt(claims: Record<string, unknown>): string {
  const part = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${part({ alg: "ES256", typ: "at+jwt" })}.${part(claims)}.sig`;
}

const issued = { status: 200, body: { access_token: jwt({ sub: "alice", scope: "orders:read" }), expires_in: 300 } };

function client(fetch: typeof globalThis.fetch) {
  const key = generateAgentKey();
  return {
    key,
    client: new BrokerClient({ brokerUrl: BROKER, agentId: "agt_1", privateKey: key.privateKey, resource: ORDERS, fetch, sleep: async () => {} }),
  };
}

describe("clientAssertion", () => {
  it("is an ES256 JWT about the agent, verifiable with its public key", () => {
    const key = generateAgentKey();

    const assertion = clientAssertion("agt_1", key.privateKey, ISSUER_TOKEN_ENDPOINT);

    const [header, payload, signature] = assertion.split(".");
    const claims = decodeClaims(assertion);
    expect(JSON.parse(Buffer.from(header, "base64url").toString())).toEqual({ alg: "ES256", typ: "JWT" });
    expect(claims).toMatchObject({ iss: "agt_1", sub: "agt_1", aud: ISSUER_TOKEN_ENDPOINT });
    expect(Number(claims.exp) - Number(claims.iat)).toBe(60);
    const valid = verify(
      "sha256",
      Buffer.from(`${header}.${payload}`),
      { key: createPublicKey({ key: key.publicJwk, format: "jwk" }), dsaEncoding: "ieee-p1363" },
      Buffer.from(signature, "base64url"),
    );
    expect(valid).toBe(true);
  });

  it("never puts the private key in the public JWK", () => {
    expect(generateAgentKey().publicJwk).not.toHaveProperty("d");
  });
});

describe("scopeFor", () => {
  it("maps each action to the one scope the Orders API requires", () => {
    expect(scopeFor({ type: "list", customer_id: "c" })).toBe("orders:read");
    expect(scopeFor({ type: "refund", order_id: "1", max_amount_cents: 1 })).toBe("orders:refund");
    expect(scopeFor({ type: "delete", order_id: "1" })).toBe("orders:delete");
  });
});

describe("BrokerClient.getToken", () => {
  const action: Action = { type: "refund", order_id: "1042", max_amount_cents: 3000 };

  it("sends a token exchange for exactly one action", async () => {
    const broker = fakeBroker([issued]);

    const token = await client(broker.fetch).client.getToken({ delegationToken: "dlg-token", action });

    const form = broker.tokenRequests[0];
    expect(form.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:token-exchange");
    expect(form.get("client_id")).toBe("agt_1");
    expect(form.get("subject_token")).toBe("dlg-token");
    expect(form.get("resource")).toBe(ORDERS);
    expect(form.get("scope")).toBe("orders:refund");
    expect(JSON.parse(form.get("authorization_details")!)).toEqual([action]);
    expect(form.get("approval_id")).toBeNull();
    // The assertion is addressed to the broker's own name for its token endpoint
    expect(decodeClaims(form.get("client_assertion")!).aud).toBe(ISSUER_TOKEN_ENDPOINT);
    expect(token.claims.sub).toBe("alice");
  });

  it("throws the broker's OAuth error when refused", async () => {
    const broker = fakeBroker([{ status: 400, body: { error: "access_denied", error_description: "Forbidden by never-delete" } }]);

    const error = await client(broker.fetch).client.getToken({ delegationToken: "d", action }).catch((e) => e);

    expect(error).toBeInstanceOf(BrokerError);
    expect(error).toMatchObject({ code: "access_denied", description: "Forbidden by never-delete", status: 400 });
  });

  it("waits for a human, then retries with the approval id", async () => {
    const pending = { status: 400, body: { error: "authorization_pending", approval_id: "apr_1", expires_in: 600, interval: 2 } };
    const broker = fakeBroker([pending, issued], ["pending", "pending", "approved"]);
    const notified: string[] = [];

    const token = await client(broker.fetch).client.getToken({
      delegationToken: "d",
      action,
      onApprovalPending: (p) => {
        notified.push(p.approvalId);
      },
    });

    expect(notified).toEqual(["apr_1"]);
    expect(broker.polls).toHaveLength(3);
    expect(broker.polls[0]).toBe(`${BROKER}/approvals/apr_1`);
    expect(broker.tokenRequests[1].get("approval_id")).toBe("apr_1");
    expect(token.claims.sub).toBe("alice");
  });

  it("reports a human's denial as the broker's error", async () => {
    const pending = { status: 400, body: { error: "authorization_pending", approval_id: "apr_1", expires_in: 600 } };
    const denied = { status: 400, body: { error: "access_denied", error_description: "A human denied this request" } };
    const broker = fakeBroker([pending, denied], ["denied"]);

    const error = await client(broker.fetch).client.getToken({ delegationToken: "d", action }).catch((e) => e);

    expect(error).toMatchObject({ code: "access_denied", description: "A human denied this request" });
  });
});
