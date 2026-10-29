-- Flyway runs this after every migrate, as the schema owner. It (re)creates the role the
-- broker runs as and grants it only what it needs. In particular the broker can insert
-- and read audit events but never update or delete them.

DO $$
BEGIN
    IF current_user = '${app_role}' THEN
        RAISE EXCEPTION 'The broker must not run as the schema owner (%)', current_user;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${app_role}') THEN
        CREATE ROLE ${app_role} LOGIN;
    END IF;
END
$$;

ALTER ROLE ${app_role} WITH LOGIN PASSWORD '${app_password}';

GRANT USAGE ON SCHEMA public TO ${app_role};
GRANT SELECT, INSERT, UPDATE ON agents, delegations, issued_tokens, approvals TO ${app_role};

REVOKE ALL ON audit_events FROM ${app_role};
GRANT SELECT, INSERT ON audit_events TO ${app_role};
