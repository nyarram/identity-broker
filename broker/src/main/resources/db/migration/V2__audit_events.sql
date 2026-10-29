-- Append-only, hash-chained record of every broker decision.
-- hash = SHA-256(prev_hash || canonical JSON of the event), so editing or deleting a row
-- breaks the chain. seq is assigned under an advisory lock and has no gaps.
create table audit_events (
    seq           bigint primary key,
    occurred_at   timestamptz not null,
    event_type    text        not null,
    agent_id      text,
    user_id       text,
    delegation_id text,
    jti           text,
    request       jsonb       not null,
    decision      text,
    reason        text,
    prev_hash     text        not null,
    hash          text        not null unique
);

create index audit_events_delegation_id on audit_events (delegation_id);
