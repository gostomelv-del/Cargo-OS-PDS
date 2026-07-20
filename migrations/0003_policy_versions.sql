BEGIN;

CREATE EXTENSION IF NOT EXISTS btree_gist;

CREATE TABLE policy_versions (
    policy_id TEXT NOT NULL CHECK (policy_id <> ''),
    version TEXT NOT NULL CHECK (version <> ''),
    schema_version TEXT NOT NULL CHECK (schema_version <> ''),
    effective_from TIMESTAMPTZ NOT NULL,
    effective_until TIMESTAMPTZ,
    policy_hash TEXT NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
    snapshot JSONB NOT NULL,
    stored_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (policy_id, version),
    CHECK (effective_until IS NULL OR effective_until > effective_from),
    EXCLUDE USING gist (
        policy_id WITH =,
        tstzrange(effective_from, effective_until, '[)') WITH &&
    )
);

CREATE INDEX policy_versions_resolution_idx
    ON policy_versions (policy_id, effective_from);

CREATE OR REPLACE FUNCTION cargoos_reject_policy_version_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Policy versions are immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER policy_versions_immutable
BEFORE UPDATE OR DELETE ON policy_versions
FOR EACH ROW EXECUTE FUNCTION cargoos_reject_policy_version_mutation();

COMMIT;
