# Agent Identity Broker

An identity broker that gives AI agents short-lived, narrowly scoped credentials, so a hijacked or prompt-injected agent can only do what its current task allows.

> Work in progress. M1 (tokens) and M2 (policy and audit) are done. Approvals, revocation and the demo agent come in M3; the full write-up comes in M4.

## Quickstart

Requires Docker. Node 20+ is only needed for the smoke test.

```bash
docker compose up -d --build --wait
node scripts/smoke-test.mjs
```

That starts Postgres, the broker (`localhost:9000`) and the mock Orders API (`localhost:8081`). The smoke test then registers an agent, delegates a task, exchanges the delegation for access tokens, checks what policy allows and denies, calls the Orders API, and verifies the audit log.

## How it works

1. An admin registers an agent with its **public** key (`POST /admin/agents`). The agent never receives a secret.
2. A human delegates a task to the agent (`POST /delegations`) and gets a **delegation token**. Its audience is the broker, so it is useless against any API.
3. For each action, the agent proves its identity with a signed JWT (private_key_jwt) and exchanges the delegation for an **access token** (RFC 8693). The request names the one action it is for, as RFC 9396 `authorization_details`, for example `{"type":"refund","order_id":"1042","max_amount_cents":3000}`.
4. The broker evaluates that action against **Cedar policies** ([policies/](policies/)): reads only within the task, refunds up to $50 automatically and above that only with approval, deletes never.
5. If permitted, the access token is valid for 5 minutes at most, works only against one API, allows only that one action, and names both the human (`sub`) and the agent (`act.sub`).
6. The Orders API validates the token against the broker's JWKS (RFC 9068 profile), checks the scope, and checks that the request matches the token's `authorization_details`: same order, amount within the limit.
7. Every issuance and denial is written to a **hash-chained audit log**. `GET /admin/audit/verify` recomputes the chain and reports the first event that was edited or removed, and the broker's database role cannot update or delete audit rows.

## Development

```bash
./gradlew test   # unit tests + Testcontainers integration tests (needs Docker)
```

Java 21 is downloaded automatically by Gradle if your JDK is older.

See [docs/decisions.md](docs/decisions.md) for design choices and [docs/spike-findings.md](docs/spike-findings.md) for what was validated before building.
