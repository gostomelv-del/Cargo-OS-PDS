package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"cargoos/audit"
	"cargoos/evaluation"
	"cargoos/migrations"
	"cargoos/pds"
)

func completedSnapshot(t *testing.T) evaluation.EvaluationSnapshot {
	t.Helper()
	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	aggregate, err := evaluation.NewEvaluation(uuid.New(), uuid.New(), base)
	if err != nil {
		t.Fatal(err)
	}
	if err = aggregate.RegisterRequiredRuleAt("weight", base); err != nil {
		t.Fatal(err)
	}
	if err = aggregate.Start(base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = aggregate.RecordRuleOutcome(evaluation.RuleOutcome{
		RuleID: "weight", Status: evaluation.RuleOutcomePass, EvaluatedAt: base.Add(2 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	result, reasons, err := aggregate.DeriveResult()
	if err != nil {
		t.Fatal(err)
	}
	if err = aggregate.CompleteAt(result, reasons, base.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := aggregate.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestSnapshotCodecRoundTrip(t *testing.T) {
	snapshot := completedSnapshot(t)
	payload, err := encodeSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(payload) {
		t.Fatal("snapshot is not valid JSON")
	}
	restored, err := decodeSnapshot(payload)
	if err != nil {
		t.Fatal(err)
	}
	if restored.ID() != snapshot.EvaluationID || restored.Version() != snapshot.Version {
		t.Fatal("snapshot identity or version changed")
	}
	if restored.Result() != evaluation.ResultVerified {
		t.Fatalf("unexpected result: %s", restored.Result())
	}
}

func TestInvalidSnapshotPayloadRejected(t *testing.T) {
	if _, err := decodeSnapshot([]byte("{")); err == nil {
		t.Fatal("expected invalid JSON error")
	}
	snapshot := completedSnapshot(t)
	snapshot.Version = 0
	if _, err := encodeSnapshot(snapshot); !errors.Is(err, evaluation.ErrSnapshotVersionRequired) {
		t.Fatalf("expected version validation error, got %v", err)
	}
}

func TestOutboxRecordValidation(t *testing.T) {
	now := time.Now().UTC()
	event := evaluation.EvaluationCreatedEvent{
		EvaluationID: uuid.New(),
		SessionID:    uuid.New(),
		CreatedAt:    now,
		Version:      1,
	}
	record, err := evaluation.NewOutboxRecord(event, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateOutboxRecord(record); err != nil {
		t.Fatal(err)
	}
	record.Payload = []byte("{")
	if err = validateOutboxRecord(record); !errors.Is(err, ErrInvalidOutboxRecord) {
		t.Fatalf("expected invalid outbox error, got %v", err)
	}
}

func TestNewStoreRejectsNilDatabase(t *testing.T) {
	if _, err := NewStore(nil); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database error, got %v", err)
	}
}

func openIntegrationStore(t *testing.T) (*sql.DB, *Store) {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is not set")
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = migrations.Apply(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return db, store
}

func TestPostgresSaveEvaluationRollsBackSnapshotWhenOutboxFails(t *testing.T) {
	db, store := openIntegrationStore(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	aggregate, err := evaluation.NewEvaluation(uuid.New(), uuid.New(), base)
	if err != nil {
		t.Fatal(err)
	}
	created, err := aggregate.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	createdRecords, err := aggregate.BuildOutboxRecords(base)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SaveEvaluation(ctx, created, 0, createdRecords); err != nil {
		t.Fatal(err)
	}
	createdHead, err := store.FindAuditHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	createdPayload, err := encodeSnapshot(created)
	if err != nil {
		t.Fatal(err)
	}
	if createdHead.Kind != audit.RecordEvaluation || createdHead.RecordRoot != sha256.Sum256(createdPayload) {
		t.Fatalf("created Evaluation was not bound to audit head: %#v", createdHead)
	}
	aggregate.ClearDomainEvents()

	if err = aggregate.Start(base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	running, err := aggregate.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	startedRecords, err := aggregate.BuildOutboxRecords(base.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	validStartedRecords := append([]evaluation.OutboxRecord(nil), startedRecords...)
	startedRecords[0].Payload = []byte("{")
	if err = store.SaveEvaluation(ctx, running, created.Version, startedRecords); !errors.Is(err, ErrInvalidOutboxRecord) {
		t.Fatalf("expected outbox validation failure, got %v", err)
	}
	headAfterFailure, err := store.FindAuditHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if headAfterFailure.Sequence != createdHead.Sequence || headAfterFailure.Root != createdHead.Root {
		t.Fatalf("failed Evaluation save advanced audit ledger: %#v", headAfterFailure)
	}

	recovered, err := store.FindEvaluation(ctx, created.EvaluationID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.State() != evaluation.StateCreated || recovered.Version() != created.Version {
		t.Fatalf("failed transaction changed stored aggregate: state=%s version=%d",
			recovered.State(), recovered.Version())
	}
	var startedCount int
	if err = db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		  FROM evaluation_outbox
		 WHERE aggregate_id = $1
		   AND aggregate_version = $2
		   AND event_type = 'EvaluationStartedEvent'
	`, created.EvaluationID.String(), running.Version).Scan(&startedCount); err != nil {
		t.Fatal(err)
	}
	if startedCount != 0 {
		t.Fatalf("failed transaction left %d started outbox records", startedCount)
	}

	if err = store.SaveEvaluation(ctx, running, created.Version, validStartedRecords); err != nil {
		t.Fatalf("retry after rollback failed: %v", err)
	}
	runningHead, err := store.FindAuditHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runningPayload, err := encodeSnapshot(running)
	if err != nil {
		t.Fatal(err)
	}
	if runningHead.Sequence != createdHead.Sequence+1 ||
		runningHead.PreviousRoot != createdHead.Root ||
		runningHead.Kind != audit.RecordEvaluation ||
		runningHead.RecordRoot != sha256.Sum256(runningPayload) {
		t.Fatalf("running Evaluation audit binding is invalid: %#v", runningHead)
	}
	recovered, err = store.FindEvaluation(ctx, created.EvaluationID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.State() != evaluation.StateRunning || recovered.Version() != running.Version {
		t.Fatalf("retry did not persist running state: state=%s version=%d",
			recovered.State(), recovered.Version())
	}
	if err = db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		  FROM evaluation_outbox
		 WHERE aggregate_id = $1
		   AND aggregate_version = $2
		   AND event_type = 'EvaluationStartedEvent'
	`, created.EvaluationID.String(), running.Version).Scan(&startedCount); err != nil {
		t.Fatal(err)
	}
	if startedCount != 1 {
		t.Fatalf("retry produced %d started outbox records", startedCount)
	}
}

func TestPostgresExpiredEvaluationRecoversAfterServiceRestart(t *testing.T) {
	_, store := openIntegrationStore(t)
	ctx := context.Background()
	createdAt := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	now := createdAt
	service := pds.NewServiceWithStore(store, func() time.Time { return now })
	created, err := service.Create(ctx, uuid.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	now = createdAt.Add(time.Minute)
	expired, err := service.ExpireTimedOut(
		ctx,
		created.EvaluationID,
		pds.TimeoutPolicy{CreatedTimeout: time.Minute},
	)
	if err != nil {
		t.Fatal(err)
	}

	restarted := pds.NewServiceWithStore(store, func() time.Time { return now.Add(time.Hour) })
	recovered, err := restarted.Snapshot(ctx, created.EvaluationID)
	if err != nil {
		t.Fatal(err)
	}
	trace, err := restarted.Trace(ctx, created.EvaluationID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.State != evaluation.StateExpired ||
		recovered.Version != expired.Version ||
		recovered.ExpiredAt == nil || expired.ExpiredAt == nil ||
		!recovered.ExpiredAt.Equal(*expired.ExpiredAt) ||
		trace.ExpiredAt == nil ||
		!trace.ExpiredAt.Equal(*expired.ExpiredAt) ||
		len(trace.ReasonCodes) != 1 ||
		trace.ReasonCodes[0] != evaluation.ReasonCodeEvaluationTimeout {
		t.Fatalf("restart changed expired Evaluation: snapshot=%#v trace=%#v", recovered, trace)
	}
}
