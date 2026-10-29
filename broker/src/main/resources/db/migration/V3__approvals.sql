-- A request that policy allows only with a human's approval. An approval is bound to the
-- exact request (agent, delegation, resource and action) through request_hash, so it cannot
-- be reused for anything else, and it can be used once.
create table approvals (
    id             text primary key,
    delegation_id  text        not null references delegations (id),
    agent_id       text        not null references agents (id),
    user_id        text        not null,
    request_hash   text        not null,
    resource       text        not null,
    action         jsonb       not null,
    policy_reason  text,
    status         text        not null check (status in ('pending', 'approved', 'denied', 'used')),
    created_at     timestamptz not null,
    expires_at     timestamptz not null,
    decided_at     timestamptz,
    decided_by     text,
    used_at        timestamptz
);

create index approvals_lookup on approvals (agent_id, delegation_id, request_hash);
create index approvals_status on approvals (status);
