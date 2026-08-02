BEGIN;

ALTER TABLE responsibility_handover_events
    ADD COLUMN audit_sequence BIGINT UNIQUE REFERENCES audit_ledger (sequence),
    ADD CONSTRAINT responsibility_handover_audit_required
        CHECK (audit_sequence IS NOT NULL) NOT VALID;

CREATE OR REPLACE FUNCTION cargoos_protect_handover_event()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Responsibility handover facts are immutable'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.object_id <> NEW.object_id OR OLD.version <> NEW.version OR
       OLD.from_participant_id <> NEW.from_participant_id OR
       OLD.to_participant_id <> NEW.to_participant_id OR
       OLD.transferred_at <> NEW.transferred_at OR
       OLD.audit_sequence IS DISTINCT FROM NEW.audit_sequence OR
       OLD.recorded_at <> NEW.recorded_at THEN
        RAISE EXCEPTION 'Responsibility handover facts are immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

COMMIT;
