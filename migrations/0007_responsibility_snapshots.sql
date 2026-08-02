BEGIN;

CREATE TABLE responsibility_snapshots (
    object_id TEXT PRIMARY KEY CHECK (object_id <> '' AND object_id = BTRIM(object_id)),
    participant_id TEXT NOT NULL CHECK (participant_id <> '' AND participant_id = BTRIM(participant_id)),
    version BIGINT NOT NULL CHECK (version > 0),
    assigned_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMIT;
