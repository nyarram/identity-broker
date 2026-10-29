#!/usr/bin/env node
// End-to-end check against a running `docker compose up`. Node 20+, no dependencies.
// Usage: node scripts/smoke-test.mjs

import { generateKeyPairSync, randomUUID, sign } from "node:crypto";

const BROKER = process.env.BROKER_URL ?? "http://localhost:9000";
const ORDERS = process.env.ORDERS_URL ?? "http://localhost:8081";
const ORDERS_AUDIENCE = "https://orders-api.example";
const ADMIN_TOKEN = process.env.BROKER_ADMIN_TOKEN ?? "dev-admin-token-not-for-production";

let failures = 0;
function check(name, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${ok || !detail ? "" : `  (${detail})`}`);
  if (!ok) failures++;
}

const b64url = (data) => Buffer.from(data).toString("base64url");
const decode = (jwt, part) => JSON.parse(Buffer.from(jwt.split(".")[part], "base64url"));

function newAgentKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { publicJwk: publicKey.export({ format: "jwk" }), privateKey };
}

// RFC 7523 client assertion, signed ES256 (JOSE wants raw r||s, not DER)
function clientAssertion(agentId, privateKey, audience) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: "ES256", typ: "JWT" }));
  const claims = b64url(JSON.stringify({ iss: agentId, sub: agentId, aud: audience, jti: randomUUID(), iat: now, exp: now + 60 }));
  const signature = sign("sha256", Buffer.from(`${header}.${claims}`), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return `${header}.${claims}.${b64url(signature)}`;
}

async function request(method, url, { json, form, bearer } = {}) {
  const headers = {};
  let body;
  if (json) { headers["Content-Type"] = "application/json"; body = JSON.stringify(json); }
  if (form) { headers["Content-Type"] = "application/x-www-form-urlencoded"; body = new URLSearchParams(form); }
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  const res = await fetch(url, { method, headers, body });
  const text = await res.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  return { status: res.status, data };
}

async function waitFor(name, probe, seconds = 120) {
  for (let i = 0; i < seconds; i++) {
    try { if (await probe()) return true; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 1000));
  }
  check(`${name} is reachable`, false, `gave up after ${seconds}s`);
  process.exit(1);
}

await waitFor("broker", async () => (await fetch(`${BROKER}/oauth2/jwks`)).ok);
await waitFor("orders-api", async () => (await fetch(`${ORDERS}/orders/1042`)).status === 401);

const metadata = (await request("GET", `${BROKER}/.well-known/oauth-authorization-server`)).data;
const tokenAudience = metadata.token_endpoint; // assertion audience uses the issuer's view of the URL
console.log(`Broker issuer: ${metadata.issuer}\n`);

async function registerAgent(name) {
  const key = newAgentKey();
  const res = await request("POST", `${BROKER}/admin/agents`, {
    bearer: ADMIN_TOKEN,
    json: { name, public_jwk: key.publicJwk, allowed_audiences: [ORDERS_AUDIENCE] },
  });
  return { res, id: res.data.id, privateKey: key.privateKey };
}

// Each token is for one action, described by one RFC 9396 authorization_details entry
async function exchange(agent, subjectToken, scope, detail) {
  return request("POST", `${BROKER}/oauth2/token`, {
    form: {
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      client_id: agent.id,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: clientAssertion(agent.id, agent.privateKey, tokenAudience),
      subject_token: subjectToken,
      subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
      resource: ORDERS_AUDIENCE,
      scope,
      authorization_details: JSON.stringify([detail]),
    },
  });
}

// 1. Register an agent with only its public key
const agent = await registerAgent("smoke-support-bot");
check("register agent with a public key", agent.res.status === 201, JSON.stringify(agent.res.data));

// 2. A human delegates a task: help Alice with order 1042
const delegation = await request("POST", `${BROKER}/delegations`, {
  bearer: ADMIN_TOKEN,
  json: {
    user_id: "alice",
    agent_id: agent.id,
    task_description: "Help Alice with her running shoes order (1042)",
    task_scope: { customer_id: "cust_alice", order_ids: ["1042"] },
    scopes: ["orders:read", "orders:refund", "orders:delete"],
  },
});
check("create delegation", delegation.status === 201, JSON.stringify(delegation.data));
const delegationToken = delegation.data.delegation_token;

// 3. The agent exchanges it for a token to read order 1042 (private_key_jwt + RFC 8693)
const exchanged = await exchange(agent, delegationToken, "orders:read", { type: "read", order_id: "1042" });
check("token exchange with private_key_jwt", exchanged.status === 200, JSON.stringify(exchanged.data));
const accessToken = exchanged.data.access_token;

const header = decode(accessToken, 0);
const claims = decode(accessToken, 1);
check("access token is ES256, typ at+jwt", header.alg === "ES256" && header.typ === "at+jwt", JSON.stringify(header));
check("sub is the human, act.sub is the agent", claims.sub === "alice" && claims.act?.sub === agent.id);
check("aud is the Orders API only", JSON.stringify([claims.aud].flat()) === JSON.stringify([ORDERS_AUDIENCE]));
check("has scope, client_id, delegation_id, jti",
  claims.scope === "orders:read" && claims.client_id === agent.id && claims.delegation_id === delegation.data.delegation_id && !!claims.jti);
check("exp - iat <= 300", claims.exp - claims.iat <= 300, `${claims.exp - claims.iat}s`);

// 4. The Orders API enforces it
const read = await request("GET", `${ORDERS}/orders/1042`, { bearer: accessToken });
check("Orders API: access token reads the order (200)", read.status === 200, `got ${read.status}`);
const readOther = await request("GET", `${ORDERS}/orders/1043`, { bearer: accessToken });
check("Orders API: the same token cannot read another order (403)", readOther.status === 403, `got ${readOther.status}`);
const withDelegation = await request("GET", `${ORDERS}/orders/1042`, { bearer: delegationToken });
check("Orders API: delegation token is rejected (401)", withDelegation.status === 401, `got ${withDelegation.status}`);
const noToken = await request("GET", `${ORDERS}/orders/1042`);
check("Orders API: no token is rejected (401)", noToken.status === 401, `got ${noToken.status}`);
const refundWithRead = await request("POST", `${ORDERS}/orders/1042/refund`, { bearer: accessToken, json: { amount_cents: 3000 } });
check("Orders API: read-only token cannot refund (403)", refundWithRead.status === 403, `got ${refundWithRead.status}`);

// 5. Policy (Cedar) decides what the broker will issue
const outOfTask = await exchange(agent, delegationToken, "orders:read", { type: "read", order_id: "1047" });
check("policy: reading an order outside the task is denied", outOfTask.data.error === "access_denied",
  `${outOfTask.status} ${JSON.stringify(outOfTask.data)}`);
const del = await exchange(agent, delegationToken, "orders:delete", { type: "delete", order_id: "1042" });
check("policy: delete is denied even though the delegation lists it", del.data.error === "access_denied",
  `${del.status} ${JSON.stringify(del.data)}`);
const bigRefund = await exchange(agent, delegationToken, "orders:refund", { type: "refund", order_id: "1042", max_amount_cents: 12000 });
check("policy: a $120 refund is not issued without approval", bigRefund.data.error === "access_denied",
  `${bigRefund.status} ${JSON.stringify(bigRefund.data)}`);

const refundGrant = await exchange(agent, delegationToken, "orders:refund", { type: "refund", order_id: "1042", max_amount_cents: 3000 });
check("policy: a $30 refund on the task order is issued", refundGrant.status === 200, JSON.stringify(refundGrant.data));
const refundToken = refundGrant.data.access_token;
const overMax = await request("POST", `${ORDERS}/orders/1042/refund`, { bearer: refundToken, json: { amount_cents: 3001 } });
check("Orders API: refund above the token's max_amount_cents is rejected (403)", overMax.status === 403, `got ${overMax.status}`);
const refunded = await request("POST", `${ORDERS}/orders/1042/refund`, { bearer: refundToken, json: { amount_cents: 3000 } });
check("Orders API: $30 refund succeeds and names user and agent",
  refunded.status === 200 && refunded.data.performed_by?.user === "alice" && refunded.data.performed_by?.agent === agent.id,
  `${refunded.status} ${JSON.stringify(refunded.data)}`);

// 6. Another agent cannot use this delegation
const rogue = await registerAgent("smoke-rogue-bot");
const stolen = await exchange(rogue, delegationToken, "orders:read", { type: "read", order_id: "1042" });
check("another agent cannot use the delegation", stolen.status === 400 && stolen.data.error === "invalid_grant",
  `${stolen.status} ${JSON.stringify(stolen.data)}`);

// 7. Everything above is in the tamper-evident audit log
const events = [];
for (let after = 0; after !== null; ) {
  const page = await request("GET", `${BROKER}/admin/audit?limit=500&after=${after}`, { bearer: ADMIN_TOKEN });
  events.push(...(page.data.events ?? []));
  after = page.data.next_after ?? null;
}
const ours = events.filter((e) => e.delegation_id === delegation.data.delegation_id);
const issued = ours.filter((e) => e.event_type === "token_issued").length;
const denied = ours.filter((e) => e.event_type === "token_denied").length;
check("audit: issued and denied tokens are recorded", issued === 2 && denied === 4, `issued=${issued} denied=${denied}`);
const verify = await request("GET", `${BROKER}/admin/audit/verify`, { bearer: ADMIN_TOKEN });
check("audit: hash chain verifies", verify.data.valid === true, JSON.stringify(verify.data));

console.log(failures === 0 ? "\nAll smoke checks passed." : `\n${failures} smoke check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
