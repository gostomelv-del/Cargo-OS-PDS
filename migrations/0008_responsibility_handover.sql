BEGIN;

CREATE TABLE responsibility_handover_events (
    object_id TEXT NOT NULL REFERENCES responsibility_snapshots (object_id),
    version BIGINT NOT NULL CHECK (version > 1),
    from_participant_id TEXT NOT NULL CHECK (from_participant_id <> ''),
    to_participant_id TEXT NOT NULL CHECK (to_participant_id <> ''),
    transferred_at TIMESTAMPTZ NOT NULL,
    delivery_status TEXT NOT NULL CHECK (delivery_status IN ('PENDING', 'PUBLISHED')),
    published_at TIMESTAMPTZ,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (object_id, version),
    CHECK (from_participant_id <> to_participant_id),
    CHECK ((delivery_status = 'PENDING' AND published_at IS NULL) OR
           (delivery_status = 'PUBLISHED' AND published_at IS NOT NULL))
);

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
       OLD.recorded_at <> NEW.recorded_at THEN
        RAISE EXCEPTION 'Responsibility handover facts are immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER responsibility_handover_facts_immutable
BEFORE UPDATE OR DELETE ON responsibility_handover_events
FOR EACH ROW EXECUTE FUNCTION cargoos_protect_handover_event();

COMMIT;
