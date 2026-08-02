BEGIN;

CREATE TABLE evidence_bundle_audit_records (
    bundle_id UUID PRIMARY KEY,
    evaluation_id UUID NOT NULL,
    session_id UUID NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL,
    bundle_root BYTEA NOT NULL UNIQUE CHECK (OCTET_LENGTH(bundle_root) = 32),
    audit_sequence BIGINT NOT NULL UNIQUE REFERENCES audit_ledger (sequence)
);

CREATE OR REPLACE FUNCTION cargoos_protect_evidence_bundle_audit()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Evidence Bundle audit records are immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER evidence_bundle_audit_immutable
BEFORE UPDATE OR DELETE ON evidence_bundle_audit_records
FOR EACH ROW EXECUTE FUNCTION cargoos_protect_evidence_bundle_audit();

COMMIT;
