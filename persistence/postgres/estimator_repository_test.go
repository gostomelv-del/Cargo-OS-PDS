package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

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
	_, store := openIntegrationStore(t)
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
	if err = store.SaveEstimatorResult(ctx, result); !errors.Is(err, estimator.ErrResultAlreadyRecorded) {
		t.Fatalf("expected immutable duplicate rejection, got %v", err)
	}
	stored, err := store.FindEstimatorResult(ctx, result.Replay.ObjectID, result.Replay.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if stored != result {
		t.Fatalf("stored estimator replay changed: %#v", stored)
	}
}
