package estimator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/spatial"
)

type testPort struct {
	estimate spatial.Estimate
	err      error
}

func (port testPort) Estimate(context.Context, Request) (spatial.Estimate, error) {
	return port.estimate, port.err
}

func estimatorFixture(t *testing.T) (Request, spatial.Estimate, time.Time) {
	t.Helper()
	observedAt := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	estimate, err := spatial.NewEstimate(spatial.EstimateInput{
		Frame: "warehouse-a/map-v2", Position: spatial.Vector3{X: 1, Y: 2, Z: 3}, Floor: 1,
		Covariance: spatial.Covariance3{XX: 0.01, YY: 0.01, ZZ: 0.02}, Confidence: 0.95,
		ObservedAt: observedAt, ProfileID: "indoor-fusion", ProfileVersion: "v4",
		CalibrationVersion: "site-a-2026-08",
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := [32]byte{1, 2, 3}
	request := Request{
		ObjectID: "parcel-42", Sequence: 1, ObservationID: uuid.New(), ObservationDigest: digest,
		ObservedAt: observedAt, ReceivedAt: observedAt.Add(time.Second), TargetFrame: estimate.Frame,
		ProfileID: estimate.ProfileID, ProfileVersion: estimate.ProfileVersion,
		CalibrationVersion: estimate.CalibrationVersion,
	}
	return request, estimate, observedAt.Add(2 * time.Second)
}

func TestExecuteBindsVersionedEstimatorResultForReplay(t *testing.T) {
	request, estimate, completedAt := estimatorFixture(t)
	result, err := Execute(context.Background(), testPort{estimate: estimate}, request, completedAt)
	if err != nil {
		t.Fatal(err)
	}
	if result.Estimate != estimate || result.Replay.ObjectID != request.ObjectID ||
		result.Replay.ObservationDigest != request.ObservationDigest ||
		result.Replay.ProfileVersion != "v4" || !result.Replay.CompletedAt.Equal(completedAt) {
		t.Fatalf("unexpected estimator result: %#v", result)
	}
}

func TestRequestRequiresExactPriorForRecursiveSequence(t *testing.T) {
	request, estimate, completedAt := estimatorFixture(t)
	request.Sequence = 2
	request.HasPrior = true
	request.Prior = estimate
	request.ObservedAt = estimate.ObservedAt.Add(time.Second)
	request.ReceivedAt = request.ObservedAt.Add(time.Second)
	estimate.ObservedAt = request.ObservedAt
	result, err := Execute(context.Background(), testPort{estimate: estimate}, request, completedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Replay.HasPrior || result.Replay.Prior != request.Prior {
		t.Fatalf("prior replay binding was lost: %#v", result.Replay)
	}
}

func TestRequestRejectsHiddenOrMissingPriorState(t *testing.T) {
	request, estimate, completedAt := estimatorFixture(t)
	request.Prior = estimate
	if _, err := Execute(context.Background(), testPort{estimate: estimate}, request, completedAt); !errors.Is(err, ErrSequenceInvalid) {
		t.Fatalf("expected hidden prior rejection, got %v", err)
	}
	request.Prior = spatial.Estimate{}
	request.Sequence = 2
	if _, err := Execute(context.Background(), testPort{estimate: estimate}, request, completedAt); !errors.Is(err, ErrSequenceInvalid) {
		t.Fatalf("expected missing prior rejection, got %v", err)
	}
}

func TestExecuteRejectsOutputVersionMismatch(t *testing.T) {
	request, estimate, completedAt := estimatorFixture(t)
	estimate.ProfileVersion = "v5"
	if _, err := Execute(context.Background(), testPort{estimate: estimate}, request, completedAt); !errors.Is(err, ErrOutputBinding) {
		t.Fatalf("expected output binding rejection, got %v", err)
	}
}

func TestExecutePropagatesEstimatorFailure(t *testing.T) {
	request, _, completedAt := estimatorFixture(t)
	want := errors.New("particle depletion")
	if _, err := Execute(context.Background(), testPort{err: want}, request, completedAt); !errors.Is(err, want) {
		t.Fatalf("expected estimator failure, got %v", err)
	}
}

func TestResultValidationRejectsReplayDrift(t *testing.T) {
	request, estimate, completedAt := estimatorFixture(t)
	result, err := Execute(context.Background(), testPort{estimate: estimate}, request, completedAt)
	if err != nil {
		t.Fatal(err)
	}
	result.Replay.ObservationDigest[0] = 0
	result.Replay.ObservationDigest[1] = 0
	result.Replay.ObservationDigest[2] = 0
	if err = result.Validate(); !errors.Is(err, ErrResultInvalid) {
		t.Fatalf("expected invalid stored result, got %v", err)
	}
}

func TestResultValidationRejectsEstimateVersionDrift(t *testing.T) {
	request, estimate, completedAt := estimatorFixture(t)
	result, err := Execute(context.Background(), testPort{estimate: estimate}, request, completedAt)
	if err != nil {
		t.Fatal(err)
	}
	result.Estimate.CalibrationVersion = "site-a-2026-09"
	if err = result.Validate(); !errors.Is(err, ErrResultInvalid) {
		t.Fatalf("expected estimate binding rejection, got %v", err)
	}
}
