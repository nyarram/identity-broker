# Pre-build spike findings (2026-10-29)

Two throwaway spikes were run in Docker before starting M1, to retire the riskiest unknowns.

## Environment

| Item | Found | Action |
| --- | --- | --- |
| Host | macOS, Apple Silicon (arm64), 16 GB RAM | — |
| Local JDK | 17 (spec needs 21) | Build and run in Docker (`gradle:8.14-jdk21`, `eclipse-temurin:21-jre`); no local install needed |
| Docker | 24.0.7, amd64 emulation available | — |
| Node | 24 | Fine for the agent (spec says 20+) |

## Spike 1: Cedar (cedar-java 4.10.0)

**Result: works.** Seven policy checks passed on both `linux/arm64` and `linux/amd64` (emulated), at 0.1–0.3 ms per decision.

- Use the `uber` classifier (`com.cedarpolicy:cedar-java:4.10.0:uber`). It bundles the native library for Linux arm64/x86_64, macOS and Windows, so no Rust toolchain is needed.
- Add `com.google.guava:guava` explicitly; the uber artifact does not put it on the compile classpath.
- Use a glibc base image (Temurin/Ubuntu), not Alpine.

**Spec bug:** `context.task_order_ids.contains(resource.id)` does not work. Cedar entity IDs are not attributes, so evaluation errors and the request is **silently denied**. Use entity references instead:

```
permit(principal is Agent, action == Action::"read", resource is Order)
  when { context.task_orders.contains(resource) };
```

- Represent money as integer cents (`amount_cents <= 5000`); Cedar has no floats.
- The double-evaluation approval logic (`human_approved` false, then true) works as specified.
- Policy tests must assert "no policy errors", not just the decision, or bugs like this pass as denials.

## Spike 2: Spring Authorization Server token exchange

**Result: works with customization.** 18/18 checks passed: private_key_jwt client auth, RFC 8693 exchange, every claim in the token table, ES256, JWKS validation, and audience separation between delegation and access tokens.

- **Versions:** Spring Boot 4.1.2 is current; Spring Authorization Server now ships inside Spring Security 7 (`spring-boot-starter-oauth2-authorization-server`). Use Boot 4.1.x, not Boot 3 as the spec says.
- **The subject token must be stored by the broker.** Spring looks up `subject_token` in its `OAuth2AuthorizationService` and requires a `Principal` attribute. `POST /delegations` must save an `OAuth2Authorization` (principal = human user, client = agent), not just mint a JWT.
- **Spring does not check that the delegation belongs to the calling agent.** With the check off, `rogue-bot` exchanged `support-bot`'s delegation token and got an access token. The broker must enforce `delegation.agent_id == client_id`.
- **Spring does not cap scopes at the delegation.** It only checks the client's registered scopes. The broker must check requested scope ⊆ delegation scope.
- **Defaults to override in a token customizer:** `aud` defaults to the client id (set it from `resource`); no `act` claim without an actor token (add `act.sub` = agent); signing defaults to RS256 (set ES256); `authorization_details` arrives in additional parameters and must be parsed and validated.
- **private_key_jwt only resolves agent keys via `jwkSetUrl`.** The spec registers an inline JWK, so either serve each agent's registered key from a broker URL (as the spike did) or provide a custom `JwtDecoderFactory` that reads the key from the agent table. Prefer the custom factory: no self-HTTP calls.
- Single-audience `aud` is serialized as a string. The Orders API validator must accept both string and array (Spring's validator does).

## Resolved during M1

- **`JdbcOAuth2AuthorizationService` serialization:** avoided. The broker implements `OAuth2AuthorizationService` over its own tables (see `docs/decisions.md`). One integration catch: claims put into token metadata must use `Instant` for `exp`/`iat`/`nbf`, not numbers or `Date`, or Spring fails with a `ClassCastException`.
- **Token introspection and revocation against Postgres:** the storage paths exist, but end-to-end tests come with M3.
