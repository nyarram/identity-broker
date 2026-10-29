-- Registered agents. Each agent proves its identity with a client assertion signed by
-- the private key matching public_jwk (private_key_jwt); there are no shared secrets.
create table agents (
    id                text primary key,
    name              text        not null,
    public_jwk        jsonb       not null,
    allowed_audiences text[]      not null,
    created_at        timestamptz not null,
    disabled_at       timestamptz
);

-- A human's grant of a task to one agent. The delegation token itself is never stored,
-- only its SHA-256 hash, so a database leak does not leak usable tokens.
create table delegations (
    id               text primary key,
    user_id          text        not null,
    agent_id         text        not null references agents (id),
    task_description text        not null,
    task_scope       jsonb       not null,
    scopes           text[]      not null,
    token_hash       text        not null unique,
    created_at       timestamptz not null,
    expires_at       timestamptz not null,
    revoked_at       timestamptz
);

create index delegations_agent_id on delegations (agent_id);

-- Every access token issued by token exchange. Used for introspection and revocation.
create table issued_tokens (
    jti           text primary key,
    token_hash    text        not null unique,
    delegation_id text        not null references delegations (id),
    agent_id      text        not null references agents (id),
    user_id       text        not null,
    audience      text        not null,
    scopes        text[]      not null,
    claims        jsonb       not null,
    issued_at     timestamptz not null,
    expires_at    timestamptz not null,
    revoked_at    timestamptz
);

create index issued_tokens_delegation_id on issued_tokens (delegation_id);
create index issued_tokens_agent_id on issued_tokens (agent_id);
