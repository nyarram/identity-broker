# Agent Identity Broker

An identity broker that gives AI agents short-lived, narrowly scoped credentials, so a hijacked or prompt-injected agent can only do what its current task allows.

> Work in progress. M1–M3 are done: tokens, policy, audit, approvals, revocation and the demo. The full write-up comes in M4.

## Quickstart

Requires Docker and Node 22+.

```bash
docker compose up -d --build --wait
npm install
npm run demo -- --replay
```

That starts Postgres, the broker (`localhost:9000`) and the mock Orders API (`localhost:8081`), then runs the demo: a customer-support agent works through four tasks, getting a fresh token from the broker for every tool call.

1. A read-only question: token issued, answered.
2. A $30 refund: allowed by policy automatically.
3. A $120 refund: waits for a human's approval, then completes.
4. **Prompt injection:** a customer note tells the agent to refund every order and delete records. The agent tries; the broker denies every out-of-task action, the audit log records each denial, and the legitimate $15 refund still goes through.

To see the same agent without the broker, holding one all-access key:

```bash
npm run demo -- --replay --no-broker
```

`--replay` scripts the model's side from a recording, so it needs no API key; every tool call still goes through the real broker and API. For a live model, set `ANTHROPIC_API_KEY` (or run `ant auth login`) and drop `--replay`; add `--manual-approve` and approve scene 3 yourself:

```bash
npm run approval-cli -- list
```

`node scripts/smoke-test.mjs` runs 29 end-to-end checks against the stack.

## How it works

1. An admin registers an agent with its **public** key (`POST /admin/agents`). The agent never receives a secret.
2. A human delegates a task to the agent (`POST /delegations`) and gets a **delegation token**. Its audience is the broker, so it is useless against any API.
3. For each action, the agent proves its identity with a signed JWT (private_key_jwt) and exchanges the delegation for an **access token** (RFC 8693). The request names the one action it is for, as RFC 9396 `authorization_details`, for example `{"type":"refund","order_id":"1042","max_amount_cents":3000}`.
4. The broker evaluates that action against **Cedar policies** ([policies/](policies/)): reads only within the task, refunds up to $50 automatically and above that only with approval, deletes never.
5. If permitted, the access token is valid for 5 minutes at most, works only against one API, allows only that one action, and names both the human (`sub`) and the agent (`act.sub`).
6. The Orders API validates the token against the broker's JWKS (RFC 9068 profile), checks the scope, and checks that the request matches the token's `authorization_details`: same order, amount within the limit.
7. Requests that policy allows only with approval return `authorization_pending` (as in the device flow, RFC 8628). A human approves with the approval CLI, and the agent's retry gets a token for exactly that request, once.
8. Before every write, the Orders API asks the broker whether the token is still active (introspection, RFC 7662). Revoking a token, a delegation, or the whole agent takes effect on the next write.
9. Every issuance, denial, approval and revocation is written to a **hash-chained audit log**. `GET /admin/audit/verify` recomputes the chain and reports the first event that was edited or removed, and the broker's database role cannot update or delete audit rows.

## Development

```bash
./gradlew test       # Java unit tests + Testcontainers integration tests (needs Docker)
npm test             # agent SDK and approval CLI (Vitest)
npm run typecheck
```

Java 21 is downloaded automatically by Gradle if your JDK is older.

See [docs/decisions.md](docs/decisions.md) for design choices and [docs/spike-findings.md](docs/spike-findings.md) for what was validated before building.
