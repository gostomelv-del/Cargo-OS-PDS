#!/usr/bin/env bash
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"

PDS_DATABASE_URL="$DATABASE_URL" go run ./cmd/pds-migrate
PDS_DATABASE_URL="$DATABASE_URL" go run ./cmd/pds-migrate

evaluation_id="00000000-0000-4000-8000-000000000001"
session_id="00000000-0000-4000-8000-000000000002"

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<SQL
INSERT INTO evaluations (
    evaluation_id, session_id, state, result, version, snapshot, created_at
) VALUES (
    '$evaluation_id', '$session_id', 'CREATED', 'UNKNOWN', 1,
    '{"Version":1}', NOW()
);

INSERT INTO evaluation_history (
    evaluation_id, version, snapshot, recorded_at
) VALUES (
    '$evaluation_id', 1, '{"Version":1}', NOW()
);

INSERT INTO evaluation_outbox (
    event_id, aggregate_type, aggregate_id, session_id,
    aggregate_version, event_type, payload, status,
    occurred_at, created_at
) VALUES
(
    '00000000-0000-4000-8000-000000000011', 'evaluation',
    '$evaluation_id', '$session_id', 1, 'EvaluationCreatedEvent',
    '{}', 'PENDING', '2026-07-20T00:00:00Z', NOW()
),
(
    '00000000-0000-4000-8000-000000000012', 'evaluation',
    '$evaluation_id', '$session_id', 2, 'EvaluationStartedEvent',
    '{}', 'PENDING', '2026-07-20T00:00:01Z', NOW()
);
SQL

if psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "
    INSERT INTO evaluations (
        evaluation_id, session_id, state, result, version, snapshot, created_at
    ) VALUES (
        '00000000-0000-4000-8000-000000000099',
        '$session_id', 'CREATED', 'UNKNOWN', 0, '{}', NOW()
    );
"; then
  echo "Expected the version constraint to reject version zero"
  exit 1
fi

stale_updates="$(psql "$DATABASE_URL" -At -v ON_ERROR_STOP=1 -c "
    WITH updated AS (
        UPDATE evaluations
           SET version = 2
         WHERE evaluation_id = '$evaluation_id'
           AND version = 99
        RETURNING 1
    )
    SELECT COUNT(*) FROM updated;
")"
test "$stale_updates" = "0"

valid_updates="$(psql "$DATABASE_URL" -At -v ON_ERROR_STOP=1 -c "
    WITH updated AS (
        UPDATE evaluations
           SET version = 2
         WHERE evaluation_id = '$evaluation_id'
           AND version = 1
        RETURNING 1
    )
    SELECT COUNT(*) FROM updated;
")"
test "$valid_updates" = "1"

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL' &
BEGIN;
SELECT event_id
  FROM evaluation_outbox
 WHERE status = 'PENDING'
 ORDER BY occurred_at
 LIMIT 1
 FOR UPDATE;
SELECT pg_sleep(5);
COMMIT;
SQL
locker_pid=$!
sleep 1

skip_locked_id="$(psql "$DATABASE_URL" -At -v ON_ERROR_STOP=1 -c "
    BEGIN;
    SELECT event_id
      FROM evaluation_outbox
     WHERE status = 'PENDING'
     ORDER BY occurred_at
     LIMIT 1
     FOR UPDATE SKIP LOCKED;
    ROLLBACK;
")"
wait "$locker_pid"

if [[ "$skip_locked_id" != *"00000000-0000-4000-8000-000000000012"* ]]; then
  echo "SKIP LOCKED did not select the unlocked outbox record"
  exit 1
fi

tables="$(psql "$DATABASE_URL" -At -v ON_ERROR_STOP=1 -c "
    SELECT COUNT(*)
      FROM information_schema.tables
     WHERE table_schema = 'public'
       AND table_name IN ('evaluations', 'evaluation_history', 'evaluation_outbox');
")"
test "$tables" = "3"

echo "PostgreSQL schema, constraints, optimistic locking, and SKIP LOCKED verified"
