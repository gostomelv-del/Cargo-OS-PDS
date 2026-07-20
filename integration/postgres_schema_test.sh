#!/usr/bin/env bash
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"

PDS_DATABASE_URL="$DATABASE_URL" go run ./cmd/pds-migrate
PDS_DATABASE_URL="$DATABASE_URL" go run ./cmd/pds-migrate

migration_count="$(psql "$DATABASE_URL" -At -v ON_ERROR_STOP=1 -c \
    "SELECT COUNT(*) FROM cargoos_schema_migrations;")"
test "$migration_count" = "6"

go test ./persistence/postgres -run TestPostgres -count=1

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
       AND table_name IN (
           'evaluations', 'evaluation_history', 'evaluation_outbox',
           'evidence_objects', 'policy_versions', 'policy_lifecycle_events',
           'trusted_verification_keys', 'trust_key_revocations'
       );
")"
test "$tables" = "8"

evidence_id="00000000-0000-4000-8000-000000000021"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "
    INSERT INTO evidence_objects (
        evidence_id, session_id, source_id, source_type, evidence_type,
        observed_at, received_at, payload_digest, snapshot
    ) VALUES (
        '$evidence_id', '$session_id', 'scale-17', 'WEIGHT_SENSOR', 'WEIGHT',
        '2026-07-20T00:00:00Z', '2026-07-20T00:00:01Z',
        'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        '{}'
    );
"

if psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "
    INSERT INTO policy_versions (
        policy_id, version, schema_version, effective_from,
        policy_hash, snapshot, signer_id
    ) VALUES (
        'partial-signature', 'v1', '1', '2026-07-20T00:00:00Z',
        'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        '{}', 'policy-authority'
    );
"; then
  echo "Expected incomplete policy signature metadata to fail"
  exit 1
fi

if psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c \
    "UPDATE evidence_objects SET source_id = 'changed' WHERE evidence_id = '$evidence_id';"; then
  echo "Expected immutable evidence update to fail"
  exit 1
fi

if psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c \
    "DELETE FROM evidence_objects WHERE evidence_id = '$evidence_id';"; then
  echo "Expected immutable evidence delete to fail"
  exit 1
fi

evidence_count="$(psql "$DATABASE_URL" -At -v ON_ERROR_STOP=1 -c \
    "SELECT COUNT(*) FROM evidence_objects WHERE evidence_id = '$evidence_id';")"
test "$evidence_count" = "1"

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "
    INSERT INTO policy_versions (
        policy_id, version, schema_version, effective_from,
        policy_hash, snapshot
    ) VALUES (
        'schema-policy', 'v1', '1', '2026-07-20T00:00:00Z',
        'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        '{}'
    );
"

if psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c \
    "UPDATE policy_versions SET version = 'changed' WHERE policy_id = 'schema-policy';"; then
  echo "Expected immutable policy update to fail"
  exit 1
fi

if psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c \
    "DELETE FROM policy_versions WHERE policy_id = 'schema-policy';"; then
  echo "Expected immutable policy delete to fail"
  exit 1
fi

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "
    INSERT INTO policy_lifecycle_events (
        policy_id, version, status, event_at, approved_by, approved_at
    ) VALUES (
        'schema-policy', 'v1', 'ACTIVE', '2026-07-20T01:00:00Z',
        'policy-review-board', '2026-07-20T00:30:00Z'
    );
"

if psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c \
    "UPDATE policy_lifecycle_events SET status = 'RETIRED' WHERE policy_id = 'schema-policy';"; then
  echo "Expected append-only lifecycle update to fail"
  exit 1
fi

if psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c \
    "DELETE FROM policy_lifecycle_events WHERE policy_id = 'schema-policy';"; then
  echo "Expected append-only lifecycle delete to fail"
  exit 1
fi

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "
    INSERT INTO trusted_verification_keys (
        signer_id, key_id, algorithm, public_key, valid_from
    ) VALUES (
        'schema-authority', 'key-1', 'ED25519', decode(repeat('ab', 32), 'hex'),
        '2026-07-20T00:00:00Z'
    );
    INSERT INTO trust_key_revocations (signer_id, key_id, revoked_at)
    VALUES ('schema-authority', 'key-1', '2026-07-20T01:00:00Z');
"

if psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c \
    "UPDATE trusted_verification_keys SET key_id = 'changed' WHERE signer_id = 'schema-authority';"; then
  echo "Expected immutable Trust Store key update to fail"
  exit 1
fi

if psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c \
    "DELETE FROM trust_key_revocations WHERE signer_id = 'schema-authority';"; then
  echo "Expected immutable key revocation delete to fail"
  exit 1
fi

echo "PostgreSQL schema, migrations, immutable evidence, policies and Trust Store, append-only lifecycle, optimistic locking, and SKIP LOCKED verified"
