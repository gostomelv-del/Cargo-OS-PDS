BEGIN;

ALTER TABLE responsibility_handover_events
    ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    ADD COLUMN lock_owner TEXT NOT NULL DEFAULT '',
    ADD COLUMN lock_until TIMESTAMPTZ,
    ADD CONSTRAINT responsibility_handover_lock_consistency CHECK (
        (lock_owner = '' AND lock_until IS NULL) OR
        (lock_owner <> '' AND lock_until IS NOT NULL)
    );

CREATE INDEX responsibility_handover_ready_idx
    ON responsibility_handover_events (transferred_at, object_id, version)
    WHERE delivery_status = 'PENDING';

COMMIT;
