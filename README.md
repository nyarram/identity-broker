# Agent Identity Broker

An identity broker that gives AI agents short-lived, narrowly scoped credentials, so a hijacked or prompt-injected agent can only do what its current task allows.

> Work in progress. M1 (tokens issued and validated) is done. Policy, audit, approvals and the demo agent come in M2–M3; the full write-up comes in M4.

## Quickstart

Requires Docker. Node 20+ is only needed for the smoke test.

```bash
docker compose up -d --build --wait
node scripts/smoke-test.mjs
```

That starts Postgres, the broker (`localhost:9000`) and the mock Orders API (`localhost:8081`). The smoke test then registers an agent, delegates a task, exchanges the delegation for an access token and calls the Orders API with it.

## How it works (M1)

1. An admin registers an agent with its **public** key (`POST /admin/agents`). The agent never receives a secret.
2. A human delegates a task to the agent (`POST /delegations`) and gets a **delegation token**. Its audience is the broker, so it is useless against any API.
3. For each action, the agent proves its identity with a signed JWT (private_key_jwt) and exchanges the delegation for an **access token** (RFC 8693). The access token is valid for 5 minutes at most, works only against one API, carries only the scopes requested, and names both the human (`sub`) and the agent (`act.sub`).
4. The Orders API validates the token against the broker's JWKS (RFC 9068 profile) and enforces scopes per endpoint.

## Development

```bash
./gradlew test   # unit tests + Testcontainers integration tests (needs Docker)
```

Java 21 is downloaded automatically by Gradle if your JDK is older.

See [docs/decisions.md](docs/decisions.md) for design choices and [docs/spike-findings.md](docs/spike-findings.md) for what was validated before building.
