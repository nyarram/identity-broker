# Design decisions

Decisions made while building, with the reason and the trade-off. Newest last.

## M1

**Spring Boot 4.1 instead of Boot 3.** The spec says Boot 3, but Boot 4.1 is current and Spring Authorization Server now ships inside Spring Security 7. Starting on the current line avoids an early migration.

**The broker stores its own tables instead of Spring's `oauth2_authorization` table.** `BrokerAuthorizationService` implements Spring's `OAuth2AuthorizationService` on top of `delegations` and `issued_tokens`. Those tables are readable, are what revocation and audit need anyway, and avoid serializing Java objects into the database. Trade-off: only the token-exchange flow is supported, which is all the broker uses.

**Tokens are stored as SHA-256 hashes, never in plain text.** Lookups hash the presented token. A database leak does not leak usable tokens.

**Agent keys are read from the database, not fetched from a `jwks_uri`.** Spring's default private_key_jwt support only fetches keys from a URL. `AgentAssertionDecoderFactory` verifies assertions against the key stored at registration. Only public EC P-256 keys are accepted, and keys with private material are rejected outright.

**The broker binds every exchange to its delegation.** Spring's token exchange checks neither that the delegation belongs to the calling agent nor that the requested scope fits inside it (found in the pre-build spike). `ExchangeRules` enforces both, and also requires exactly one known `resource` (RFC 8707) that the agent is registered for.

**`scope` is required on every exchange.** Without it Spring would grant the delegation's full scope. Requiring it keeps each token as narrow as the action it is for.

**A subject token must be a delegation token.** The broker looks up both delegations and access tokens by hash, so without this rule an agent could trade an access token for a fresh one and extend its lifetime.

**Access tokens never outlive their delegation.** `exp` is the earlier of five minutes and the delegation's expiry.

**Token formats follow RFC 9068.** Access tokens have `typ: at+jwt`, a `client_id` claim (the agent), and `scope` as a space-separated string. Delegation tokens have `typ: dlg+jwt` and `aud` set to the broker. The Orders API uses Spring's RFC 9068 validator, so a delegation token fails on both type and audience.

**Money is integer cents everywhere** (`amount_cents`, and `max_amount_cents` in `authorization_details`). Cedar has no floating point, and cents avoid rounding bugs.

**Errors use OAuth codes.** Refusals return `invalid_grant`, `invalid_scope`, `invalid_target` (RFC 8707) or `invalid_authorization_details` (RFC 9396), so standard clients can understand them.

**Client assertions are limited to a five-minute lifetime** but their `jti` is not tracked for replay in v1. RFC 7523 makes replay tracking optional; it is listed for the threat model.

**Compose binds ports to 127.0.0.1 and ships a dev admin token default.** `docker compose up` works with no setup, as M1 requires. The default token is fine on localhost only; `.env.example` shows how to override it before exposing anything.

**The issuer is `http://broker:9000` in Compose,** the name other containers use. The host reaches the broker on `localhost:9000`; clients take the assertion audience from the broker's metadata, so the two names do not conflict.

**One Dockerfile for both services**, selected with `--build-arg SERVICE=...`. Images run as a non-root user. The broker's signing key is kept in a named volume with owner-only permissions, so tokens survive restarts.

**Gradle downloads a JDK 21 toolchain** (foojay resolver) when the machine has an older JDK, so `./gradlew test` works without installing Java 21.

## M2

**Every token is for exactly one action.** The exchange must carry one RFC 9396 `authorization_details` entry (`read`, `list`, `refund`, `cancel` or `delete`, with its order or customer), and `scope` must be exactly that action's scope. This is what lets policy and the Orders API reason about a specific order; a bare `orders:read` token could read anything. Unknown fields are rejected rather than ignored.

**Policies are validated against a Cedar schema at startup, and every request at evaluation time.** Cedar skips policies that fail to evaluate, which silently denies; the original spec's `resource.id` policy did exactly that. With schema validation the broker refuses to start instead. Evaluation errors that still slip through are logged at error level and denied.

**Every policy needs an `@id`.** The id is the reason recorded in the audit log, for example `Forbidden by never-delete`.

**Two policies were added to the spec's illustrative set:** listing a customer's orders is limited to the task's customer, and cancelling a task order always needs human approval. Without a cancel rule the Orders API's cancel endpoint would be unusable.

**Requests that need approval are denied with `access_denied` until M3,** which turns them into `authorization_pending` with an approval request. The two-pass evaluation (`human_approved` false, then true) is already in place and tested.

**Policy denials use the `access_denied` error code.** RFC 6749 defines it for the authorization endpoint; it is the closest standard code for a refused token request, and keeps `invalid_scope` for malformed scope requests.

**The Orders API checks `authorization_details` on every request, not only refunds.** A token for reading order 1042 cannot read 1043, even with `orders:read`. The grant is checked before the order is looked up, so a token cannot reveal whether other orders exist.

**Audit hashing uses RFC 8785 canonical JSON, implemented in-house for a restricted value set.** Audit events contain only strings, whole numbers, booleans, null, objects and arrays; floating point, the hard part of JCS, is rejected. About 80 lines with tests, against a dependency for a corner of it. Raw request parameters such as `authorization_details` are stored as strings, so a malformed request can always be audited.

**Appends are serialized with a Postgres advisory lock,** and `seq` is assigned under it, so the chain never forks and has no gaps (a gap means a deleted event). A concurrency test appends from 8 threads and verifies the chain.

**The broker runs as a restricted database role.** Flyway migrates as the schema owner; `afterMigrate.sql` creates the `broker_app` role on every start and grants it SELECT and INSERT only on `audit_events`. It refuses to run if the app role is the owner. The role's password is passed as a Flyway placeholder, so it must not contain a single quote.

**Issuance is audited fail-closed, denials fail-open.** The token is recorded and audited in one transaction before it is returned; if the audit write fails, no token is issued. A denial is still refused if its audit write fails, because refusing is the safe direction; the failure is logged.

**Failed client authentication is audited without trusting the claimed agent.** `agent_id` is set only after the agent has proved its identity; the claimed `client_id` is kept in the request summary.

**Spring clears the security context before token-endpoint errors reach the handler,** so the authenticated agent is remembered as a request attribute by a replacement client-authentication success handler. The policy decision is carried from the token customizer to where the token is saved in the same way (`GrantHolder`).

**`invalid_client` responses carry only the error code, with 401,** as Spring does by default, so a caller cannot probe which agents exist. The audit log keeps the full reason.

**Policy hot-reload is not implemented.** The spec asks for reload on file change in dev; restarting the broker takes a few seconds, and a reload path is one more thing that can load an unvalidated policy.

## M3

**Approvals are bound to the exact request and used once.** An approval stores a hash of the agent, delegation, resource and `authorization_details`; a retry must match it exactly, so approving a $120 refund on order 1045 cannot be stretched to $130 or to another order. Consuming it is a conditional update, so two concurrent retries cannot both get a token. The policy is re-checked (with `human_approved = true`) on redemption, so a policy change in the meantime still applies.

**The approval flow follows the device flow (RFC 8628).** The token endpoint answers `authorization_pending` with an `approval_id`, `expires_in` and `interval`; the agent polls `GET /approvals/{id}` and retries the exchange with `approval_id` once the status changes. Polling the status endpoint instead of the token endpoint keeps the audit log free of one denial per poll. Retries of the same request reuse the pending approval rather than opening new ones.

**`GET /approvals/{id}` needs no authentication.** The id is 80 random bits and the response holds only the status and expiry. Requiring private_key_jwt here would add a second client-authentication path for no information gain.

**Decision and collection windows:** a human has 10 minutes to decide; after approval the agent has 5 minutes to collect its token. An expired approval is derived from `expires_at`, never stored, so expiry needs no background job.

**Approving is an admin action in v1.** Anyone with the admin token can approve, and `decided_by` is self-reported. The roadmap's OIDC login would let only the delegating human approve. Listed in the threat model.

**Only resource servers can introspect, and only tokens issued for them.** Spring's introspection lets any authenticated client introspect any token. A wrapper returns `active: false` unless the caller is a configured resource server and the token's audience is that resource. Agents and other APIs learn nothing.

**Resource servers authenticate with a client secret** (`client_secret_basic`, stored as a bcrypt hash). The no-shared-secrets rule is about agents, the untrusted party; the Orders API is infrastructure, and a secret keeps its configuration to one environment variable. Spring requires a grant type on every client, so these clients carry `client_credentials`, but the broker refuses to issue tokens through anything except token exchange.

**Three levels of revocation, all through introspection:** a token (`POST /admin/tokens/{jti}/revoke`), a delegation (`POST /admin/delegations/{id}/revoke`, which also stops new exchanges) and an agent (`POST /admin/agents/{id}/disable`, which also stops client authentication). Agents can revoke their own tokens through RFC 7009 `/oauth2/revoke`. Every revocation is audited.

**The Orders API introspects before writes only, and fails closed.** Reads are validated locally and rely on the 5-minute lifetime; a revoked token can keep reading until it expires (tested, and in the threat model). If the broker cannot be reached, writes are refused with 503.

**Error responses must pass the Orders API's own security rules.** Spring renders error statuses through `/error`; with `denyAll()` as the fallback rule every 401, 409 and 422 turned into a 403. `/error` is now permitted, with a regression test.

**The demo's `--no-broker` mode uses a real all-access key on the Orders API** (`Authorization: ApiKey ...`), enabled only when `ORDERS_DEMO_API_KEY` is set. The same key resets the mock orders between runs. It exists to show the contrast and is off by default outside Compose.

**`--replay` scripts the model, not the system.** The recorded turns (`demo-agent/fixtures/replay.json`) are what the model says and which tools it calls; every tool call still goes through the real SDK, broker, policy, API and audit log. Scene 4's recording follows the injected note on purpose, playing a compromised agent. `--record <file>` captures a live model's turns in the same format.

**The live demo defaults to `claude-opus-5-5`** (override with `DEMO_MODEL`), with server-side refusal fallback on (`fallbacks: "default"`). A current model will often ignore the injected note, which is good for users and dull for a demo; `--gullible` adds a system-prompt line telling the agent to follow staff notes in orders, to simulate a badly configured agent. The broker's containment does not depend on either.

**The agent SDK has no runtime dependencies.** Node's `crypto` signs ES256 assertions (`dsaEncoding: "ieee-p1363"` for JOSE's raw signature format) and `fetch` does the rest. The TypeScript packages run from source with `tsx`, so there is no build step.

**Node 22 is the minimum,** not the spec's 20: Vitest 5 requires Node 22.12 or later.
