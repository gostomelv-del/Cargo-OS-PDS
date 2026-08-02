package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/audit"
	"cargoos/estimator"
	"cargoos/responsibility"
	"cargoos/spatial"
)

func TestEstimatorRepositoryRequiresDatabase(t *testing.T) {
	var store *Store
	if err := store.SaveEstimatorResult(context.Background(), estimator.Result{}); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database-required error, got %v", err)
	}
	if _, err := store.FindEstimatorResult(context.Background(), "parcel-42", 1); !errors.Is(err, ErrDatabaseRequired) {
		t.Fatalf("expected database-required error, got %v", err)
	}
}

func TestPostgresEstimatorResultIsImmutableAndReplayable(t *testing.T) {
	db, store := openIntegrationStore(t)
	observedAt := time.Now().UTC().Truncate(time.Microsecond)
	estimateValue, err := spatial.NewEstimate(spatial.EstimateInput{
		Frame: "warehouse-a/map-v2", Position: spatial.Vector3{X: 1, Y: 2, Z: 3}, Floor: 1,
		Covariance: spatial.Covariance3{XX: 0.01, YY: 0.01, ZZ: 0.02}, Confidence: 0.95,
		ObservedAt: observedAt, ProfileID: "indoor-fusion", ProfileVersion: "v4",
		CalibrationVersion: "site-a-2026-08",
	})
	if err != nil {
		t.Fatal(err)
	}
	objectID, err := responsibility.NewPhysicalObjectID("integration-parcel-" + uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}
	result := estimator.Result{
		Estimate: estimateValue,
		Replay: estimator.ReplayMetadata{
			ObjectID: objectID, Sequence: 1,
			ObservationID: uuid.New(), ObservationDigest: [32]byte{1, 2, 3, 4},
			ObservedAt: observedAt, ReceivedAt: observedAt.Add(time.Second),
			TargetFrame: estimateValue.Frame, ProfileID: estimateValue.ProfileID,
			ProfileVersion:     estimateValue.ProfileVersion,
			CalibrationVersion: estimateValue.CalibrationVersion,
			CompletedAt:        observedAt.Add(2 * time.Second),
		},
	}
	ctx := context.Background()
	if err = store.SaveEstimatorResult(ctx, result); err != nil {
		t.Fatal(err)
	}
	head, err := store.FindAuditHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if head.Kind != audit.RecordEstimator || head.RecordRoot != sha256.Sum256(payload) {
		t.Fatalf("estimator result was not bound to audit head: %#v", head)
	}
	if err = store.SaveEstimatorResult(ctx, result); !errors.Is(err, estimator.ErrResultAlreadyRecorded) {
		t.Fatalf("expected immutable duplicate rejection, got %v", err)
	}
	headAfterDuplicate, err := store.FindAuditHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if headAfterDuplicate.Root != head.Root || headAfterDuplicate.Sequence != head.Sequence {
		t.Fatalf("duplicate execution advanced audit ledger: %#v", headAfterDuplicate)
	}
	if _, err = db.ExecContext(ctx, `
		UPDATE estimator_results SET result = result
		 WHERE object_id = $1 AND sequence = $2
	`, result.Replay.ObjectID.String(), result.Replay.Sequence); err == nil {
		t.Fatal("expected immutable estimator result update rejection")
	}
	stored, err := store.FindEstimatorResult(ctx, result.Replay.ObjectID, result.Replay.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if stored != result {
		t.Fatalf("stored estimator replay changed: %#v", stored)
	}
}
