BEGIN;

CREATE TABLE estimator_results (
    object_id TEXT NOT NULL CHECK (object_id <> '' AND object_id = BTRIM(object_id)),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    observation_id UUID NOT NULL,
    observation_digest BYTEA NOT NULL CHECK (OCTET_LENGTH(observation_digest) = 32),
    profile_id TEXT NOT NULL CHECK (profile_id <> '' AND profile_id = BTRIM(profile_id)),
    profile_version TEXT NOT NULL CHECK (profile_version <> '' AND profile_version = BTRIM(profile_version)),
    calibration_version TEXT NOT NULL CHECK (calibration_version <> '' AND calibration_version = BTRIM(calibration_version)),
    observed_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL CHECK (completed_at >= observed_at),
    result JSONB NOT NULL CHECK (JSONB_TYPEOF(result) = 'object'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (object_id, sequence),
    UNIQUE (observation_id)
);

COMMIT;
