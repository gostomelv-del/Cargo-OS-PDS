BEGIN;

ALTER TABLE evaluations
    ALTER COLUMN snapshot TYPE BYTEA USING convert_to(snapshot::text, 'UTF8');

CREATE TABLE evaluation_audit_records (
    evaluation_id UUID NOT NULL REFERENCES evaluations (evaluation_id),
    version BIGINT NOT NULL CHECK (version > 0),
    audit_sequence BIGINT NOT NULL UNIQUE REFERENCES audit_ledger (sequence),
    PRIMARY KEY (evaluation_id, version)
);

CREATE OR REPLACE FUNCTION cargoos_protect_evaluation_audit_record()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Evaluation audit bindings are immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER evaluation_audit_records_immutable
BEFORE UPDATE OR DELETE ON evaluation_audit_records
FOR EACH ROW EXECUTE FUNCTION cargoos_protect_evaluation_audit_record();

COMMIT;
