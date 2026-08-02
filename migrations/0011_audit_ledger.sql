BEGIN;

CREATE TABLE audit_ledger (
    sequence BIGINT PRIMARY KEY CHECK (sequence > 0),
    record_kind SMALLINT NOT NULL CHECK (record_kind BETWEEN 1 AND 4),
    previous_root BYTEA NOT NULL CHECK (OCTET_LENGTH(previous_root) = 32),
    record_root BYTEA NOT NULL CHECK (OCTET_LENGTH(record_root) = 32),
    occurred_at TIMESTAMPTZ NOT NULL,
    root BYTEA NOT NULL UNIQUE CHECK (OCTET_LENGTH(root) = 32),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((sequence = 1 AND previous_root = decode(repeat('00', 32), 'hex')) OR
           (sequence > 1 AND previous_root <> decode(repeat('00', 32), 'hex')))
);

CREATE OR REPLACE FUNCTION cargoos_validate_audit_append()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    head_sequence BIGINT;
    head_root BYTEA;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('cargoos:audit-ledger'));
    SELECT sequence, root INTO head_sequence, head_root
      FROM audit_ledger ORDER BY sequence DESC LIMIT 1;
    IF NOT FOUND THEN
        IF NEW.sequence <> 1 OR NEW.previous_root <> decode(repeat('00', 32), 'hex') THEN
            RAISE EXCEPTION 'Invalid audit ledger genesis'
                USING ERRCODE = '40001';
        END IF;
    ELSIF NEW.sequence <> head_sequence + 1 OR NEW.previous_root <> head_root THEN
        RAISE EXCEPTION 'Audit ledger head changed'
            USING ERRCODE = '40001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_ledger_append_guard
BEFORE INSERT ON audit_ledger
FOR EACH ROW EXECUTE FUNCTION cargoos_validate_audit_append();

CREATE OR REPLACE FUNCTION cargoos_protect_audit_ledger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Audit ledger entries are immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER audit_ledger_immutable
BEFORE UPDATE OR DELETE ON audit_ledger
FOR EACH ROW EXECUTE FUNCTION cargoos_protect_audit_ledger();

COMMIT;
