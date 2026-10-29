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

async function exchange(agent, subjectToken, scope) {
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
    },
  });
}

// 1. Register an agent with only its public key
const agent = await registerAgent("smoke-support-bot");
check("register agent with a public key", agent.res.status === 201, JSON.stringify(agent.res.data));

// 2. A human delegates a read-only task
const delegation = await request("POST", `${BROKER}/delegations`, {
  bearer: ADMIN_TOKEN,
  json: {
    user_id: "alice",
    agent_id: agent.id,
    task_description: "Answer Alice's question about order 1042",
    task_scope: { customer_id: "cust_alice", order_ids: ["1042"] },
    scopes: ["orders:read"],
  },
});
check("create delegation", delegation.status === 201, JSON.stringify(delegation.data));
const delegationToken = delegation.data.delegation_token;

// 3. The agent exchanges it (private_key_jwt + RFC 8693)
const exchanged = await exchange(agent, delegationToken, "orders:read");
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
const withDelegation = await request("GET", `${ORDERS}/orders/1042`, { bearer: delegationToken });
check("Orders API: delegation token is rejected (401)", withDelegation.status === 401, `got ${withDelegation.status}`);
const noToken = await request("GET", `${ORDERS}/orders/1042`);
check("Orders API: no token is rejected (401)", noToken.status === 401, `got ${noToken.status}`);
const refund = await request("POST", `${ORDERS}/orders/1042/refund`, { bearer: accessToken, json: { amount_cents: 3000 } });
check("Orders API: read-only token cannot refund (403)", refund.status === 403, `got ${refund.status}`);

// 5. Another agent cannot use this delegation
const rogue = await registerAgent("smoke-rogue-bot");
const stolen = await exchange(rogue, delegationToken, "orders:read");
check("another agent cannot use the delegation", stolen.status === 400 && stolen.data.error === "invalid_grant",
  `${stolen.status} ${JSON.stringify(stolen.data)}`);

console.log(failures === 0 ? "\nAll smoke checks passed." : `\n${failures} smoke check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
