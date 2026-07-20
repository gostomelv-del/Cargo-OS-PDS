BEGIN;

CREATE TABLE evaluations (
    evaluation_id UUID PRIMARY KEY,
    session_id UUID NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('CREATED', 'RUNNING', 'COMPLETED', 'CANCELLED', 'EXPIRED')),
    result TEXT NOT NULL CHECK (result IN (
        'UNKNOWN', 'VERIFIED', 'VERIFIED_WITH_EXCEPTION',
        'REJECTED', 'MANUAL_REVIEW', 'SYSTEM_EXCEPTION'
    )),
    version BIGINT NOT NULL CHECK (version > 0),
    snapshot JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX evaluations_session_id_idx ON evaluations (session_id);
CREATE INDEX evaluations_state_updated_at_idx ON evaluations (state, updated_at);

CREATE TABLE evaluation_history (
    evaluation_id UUID NOT NULL REFERENCES evaluations (evaluation_id) ON DELETE CASCADE,
    version BIGINT NOT NULL CHECK (version > 0),
    snapshot JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (evaluation_id, version)
);

CREATE TABLE evaluation_outbox (
    event_id UUID PRIMARY KEY,
    aggregate_type TEXT NOT NULL,
    aggregate_id UUID NOT NULL,
    session_id UUID NOT NULL,
    aggregate_version BIGINT NOT NULL CHECK (aggregate_version > 0),
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'PENDING', 'PUBLISHING', 'PUBLISHED',
        'RETRY_SCHEDULED', 'DEAD_LETTERED'
    )),
    occurred_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    publishing_started_at TIMESTAMPTZ,
    published_at TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ,
    last_attempt_at TIMESTAMPTZ,
    dead_lettered_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts INTEGER NOT NULL DEFAULT 10 CHECK (max_attempts > 0),
    last_error TEXT NOT NULL DEFAULT '',
    lock_owner TEXT NOT NULL DEFAULT '',
    lock_until TIMESTAMPTZ
);

CREATE INDEX evaluation_outbox_ready_idx
    ON evaluation_outbox (status, next_attempt_at, occurred_at)
    WHERE status IN ('PENDING', 'RETRY_SCHEDULED');

CREATE INDEX evaluation_outbox_lock_idx
    ON evaluation_outbox (lock_until)
    WHERE status = 'PUBLISHING';

CREATE INDEX evaluation_outbox_aggregate_idx
    ON evaluation_outbox (aggregate_id, aggregate_version);

COMMIT;
