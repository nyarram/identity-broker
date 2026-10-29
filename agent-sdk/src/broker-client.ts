import type { KeyObject } from "node:crypto";
import { clientAssertion, decodeClaims } from "./keys.ts";

/** The one action a token is for (an RFC 9396 authorization_details entry). Amounts are cents. */
export type Action =
  | { type: "read"; order_id: string }
  | { type: "list"; customer_id: string }
  | { type: "refund"; order_id: string; max_amount_cents: number }
  | { type: "cancel"; order_id: string }
  | { type: "delete"; order_id: string };

const SCOPES: Record<Action["type"], string> = {
  read: "orders:read",
  list: "orders:read",
  refund: "orders:refund",
  cancel: "orders:cancel",
  delete: "orders:delete",
};

export function scopeFor(action: Action): string {
  return SCOPES[action.type];
}

export interface AccessToken {
  token: string;
  expiresAt: Date;
  claims: Record<string, unknown>;
}

/** The broker refused, with its OAuth error code (access_denied, invalid_scope, ...) and reason. */
export class BrokerError extends Error {
  constructor(
    readonly code: string,
    readonly description: string,
    readonly status: number,
  ) {
    super(`${code}: ${description}`);
    this.name = "BrokerError";
  }
}

export interface ApprovalPending {
  approvalId: string;
  expiresInSeconds: number;
}

export interface BrokerClientOptions {
  /** Where this agent reaches the broker. May differ from the broker's issuer URL. */
  brokerUrl: string;
  agentId: string;
  privateKey: KeyObject;
  /** The API the tokens are for (RFC 8707 resource indicator). */
  resource: string;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
}

export interface TokenRequest {
  /** The delegation token a human issued for this task. Its audience is the broker only. */
  delegationToken: string;
  action: Action;
  /** Called once when a human must approve. Polling continues until they decide or it expires. */
  onApprovalPending?: (pending: ApprovalPending) => void | Promise<void>;
}

const TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

/**
 * How an agent gets credentials: for every action, exchange the delegation for a token that
 * allows exactly that action, for at most five minutes (RFC 8693 token exchange).
 */
export class BrokerClient {
  private readonly fetch: typeof fetch;
  private readonly sleep: (ms: number) => Promise<void>;
  private tokenEndpoint?: string;

  constructor(private readonly options: BrokerClientOptions) {
    this.fetch = options.fetch ?? globalThis.fetch;
    this.sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  }

  async getToken(request: TokenRequest): Promise<AccessToken> {
    const first = await this.exchange(request.action, request.delegationToken);
    if (first.ok) {
      return first.token;
    }
    if (first.error.error !== "authorization_pending") {
      throw toBrokerError(first.error, first.status);
    }

    const approvalId = String(first.error.approval_id);
    await request.onApprovalPending?.({ approvalId, expiresInSeconds: Number(first.error.expires_in ?? 0) });
    await this.waitForDecision(approvalId, Number(first.error.interval ?? 2));

    const retry = await this.exchange(request.action, request.delegationToken, approvalId);
    if (retry.ok) {
      return retry.token;
    }
    throw toBrokerError(retry.error, retry.status);
  }

  /** Polls the approval until a human decides or it expires (RFC 8628-style). */
  private async waitForDecision(approvalId: string, intervalSeconds: number): Promise<void> {
    for (;;) {
      const response = await this.fetch(`${this.options.brokerUrl}/approvals/${encodeURIComponent(approvalId)}`);
      const { status } = (await response.json()) as { status: string };
      if (status !== "pending") {
        return; // approved, denied or expired: the retry tells the agent which, in OAuth terms
      }
      await this.sleep(intervalSeconds * 1000);
    }
  }

  private async exchange(
    action: Action,
    delegationToken: string,
    approvalId?: string,
  ): Promise<{ ok: true; token: AccessToken } | { ok: false; status: number; error: Record<string, unknown> }> {
    const form = new URLSearchParams({
      grant_type: TOKEN_EXCHANGE,
      client_id: this.options.agentId,
      client_assertion_type: JWT_BEARER,
      client_assertion: clientAssertion(this.options.agentId, this.options.privateKey, await this.assertionAudience()),
      subject_token: delegationToken,
      subject_token_type: JWT_TOKEN_TYPE,
      resource: this.options.resource,
      scope: scopeFor(action),
      authorization_details: JSON.stringify([action]),
    });
    if (approvalId) {
      form.set("approval_id", approvalId);
    }
    const response = await this.fetch(`${this.options.brokerUrl}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form,
    });
    const body = (await response.json()) as Record<string, unknown>;
    if (!response.ok) {
      return { ok: false, status: response.status, error: body };
    }
    const token = String(body.access_token);
    return {
      ok: true,
      token: { token, expiresAt: new Date(Date.now() + Number(body.expires_in) * 1000), claims: decodeClaims(token) },
    };
  }

  /**
   * Assertions are addressed to the token endpoint as the broker names it (its issuer),
   * which can differ from the URL this agent uses to reach it, for example inside Docker.
   */
  private async assertionAudience(): Promise<string> {
    if (!this.tokenEndpoint) {
      const response = await this.fetch(`${this.options.brokerUrl}/.well-known/oauth-authorization-server`);
      const metadata = (await response.json()) as { token_endpoint: string };
      this.tokenEndpoint = metadata.token_endpoint;
    }
    return this.tokenEndpoint;
  }
}

function toBrokerError(error: Record<string, unknown>, status: number): BrokerError {
  return new BrokerError(String(error.error ?? "unknown_error"), String(error.error_description ?? ""), status);
}
