BEGIN;

ALTER TABLE estimator_results
    DROP CONSTRAINT estimator_results_result_check;

ALTER TABLE estimator_results
    ALTER COLUMN result TYPE BYTEA USING convert_to(result::text, 'UTF8');

ALTER TABLE estimator_results
    ADD COLUMN audit_sequence BIGINT UNIQUE REFERENCES audit_ledger (sequence),
    ADD CONSTRAINT estimator_results_audit_required
        CHECK (audit_sequence IS NOT NULL) NOT VALID;

CREATE OR REPLACE FUNCTION cargoos_protect_estimator_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Estimator results are immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER estimator_results_immutable
BEFORE UPDATE OR DELETE ON estimator_results
FOR EACH ROW EXECUTE FUNCTION cargoos_protect_estimator_result();

COMMIT;
