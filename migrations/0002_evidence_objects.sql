BEGIN;

CREATE TABLE evidence_objects (
    evidence_id UUID PRIMARY KEY,
    session_id UUID NOT NULL,
    source_id TEXT NOT NULL CHECK (source_id <> ''),
    source_type TEXT NOT NULL CHECK (source_type <> ''),
    evidence_type TEXT NOT NULL CHECK (evidence_type ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    observed_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    payload_digest TEXT NOT NULL CHECK (payload_digest ~ '^sha256:[0-9a-f]{64}$'),
    snapshot JSONB NOT NULL,
    stored_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (received_at >= observed_at)
);

CREATE INDEX evidence_objects_session_time_idx
    ON evidence_objects (session_id, observed_at, evidence_id);

CREATE INDEX evidence_objects_source_time_idx
    ON evidence_objects (source_id, observed_at, evidence_id);

CREATE OR REPLACE FUNCTION cargoos_reject_evidence_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Evidence objects are immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER evidence_objects_immutable
BEFORE UPDATE OR DELETE ON evidence_objects
FOR EACH ROW EXECUTE FUNCTION cargoos_reject_evidence_mutation();

COMMIT;
