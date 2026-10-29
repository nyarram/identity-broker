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
