BEGIN;

CREATE TABLE policy_lifecycle_events (
    event_id BIGSERIAL PRIMARY KEY,
    policy_id TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'RETIRED')),
    event_at TIMESTAMPTZ NOT NULL,
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (policy_id, version) REFERENCES policy_versions (policy_id, version),
    UNIQUE (policy_id, version, status),
    CHECK (
        (status = 'ACTIVE' AND num_nulls(approved_by, approved_at) = 0
            AND approved_by <> '' AND approved_at <= event_at)
        OR
        (status <> 'ACTIVE' AND num_nulls(approved_by, approved_at) = 2)
    )
);

CREATE INDEX policy_lifecycle_latest_idx
    ON policy_lifecycle_events (policy_id, version, event_at DESC, event_id DESC);

CREATE OR REPLACE FUNCTION cargoos_reject_policy_lifecycle_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Policy lifecycle events are append-only'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER policy_lifecycle_events_immutable
BEFORE UPDATE OR DELETE ON policy_lifecycle_events
FOR EACH ROW EXECUTE FUNCTION cargoos_reject_policy_lifecycle_mutation();

COMMIT;
