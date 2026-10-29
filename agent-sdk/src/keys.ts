import { createPrivateKey, generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";

/** An agent's identity: a P-256 key pair. The broker only ever sees the public half. */
export interface AgentKey {
  privateKey: KeyObject;
  publicJwk: JsonWebKey;
}

export function generateAgentKey(): AgentKey {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { privateKey, publicJwk: publicKey.export({ format: "jwk" }) };
}

/** Loads a private key saved as a JWK (for example from a secrets manager). */
export function importPrivateJwk(jwk: JsonWebKey): KeyObject {
  return createPrivateKey({ key: jwk, format: "jwk" });
}

const base64url = (data: string | Buffer) => Buffer.from(data).toString("base64url");

/**
 * An RFC 7523 client assertion: a short-lived JWT, signed with the agent's private key,
 * that authenticates the agent to the broker (private_key_jwt). No shared secret exists.
 */
export function clientAssertion(agentId: string, privateKey: KeyObject, audience: string, lifetimeSeconds = 60): string {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: "ES256", typ: "JWT" }));
  const claims = base64url(
    JSON.stringify({ iss: agentId, sub: agentId, aud: audience, jti: randomUUID(), iat: now, exp: now + lifetimeSeconds }),
  );
  // JOSE wants the raw r||s signature, not DER
  const signature = sign("sha256", Buffer.from(`${header}.${claims}`), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return `${header}.${claims}.${base64url(signature)}`;
}

/** Reads a JWT's claims without verifying it. For display only; the API verifies tokens. */
export function decodeClaims(jwt: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString("utf8"));
}
