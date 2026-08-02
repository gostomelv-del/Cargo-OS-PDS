package spatial

import (
	"errors"
	"math"
	"testing"
	"time"
)

func admissibilityFixture(t *testing.T) (Estimate, Estimate, AdmissibilityPolicy, time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	objectInput := validEstimateInput()
	objectInput.Position = Vector3{X: 0, Y: 0, Z: 0}
	objectInput.ObservedAt = now.Add(-time.Second)
	participantInput := objectInput
	participantInput.Position = Vector3{X: 3, Y: 4, Z: 0}
	object, err := NewEstimate(objectInput)
	if err != nil {
		t.Fatal(err)
	}
	participant, err := NewEstimate(participantInput)
	if err != nil {
		t.Fatal(err)
	}
	policy := AdmissibilityPolicy{
		MinConfidence: 0.9, MaxAge: 5 * time.Second, FutureTolerance: time.Second,
		MaxDistance: 5, MaxTrace: 0.2,
	}
	return object, participant, policy, now
}

func TestAdmissibilityAcceptsExactBoundaries(t *testing.T) {
	object, participant, policy, now := admissibilityFixture(t)
	object.ObservedAt = now.Add(-policy.MaxAge)
	participant.ObservedAt = now.Add(policy.FutureTolerance)
	result, err := EvaluateAdmissibility(object, participant, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Admissible || result.Failures != FailureNone || result.Distance != 5 {
		t.Fatalf("expected boundary admission, got %#v", result)
	}
}

func TestAdmissibilityReturnsDeterministicFailureMask(t *testing.T) {
	object, participant, policy, now := admissibilityFixture(t)
	participant.Frame = "vehicle/map-v1"
	participant.Floor++
	participant.Confidence = 0.5
	participant.ObservedAt = now.Add(-10 * time.Second)
	participant.Covariance = Covariance3{XX: 0.2, YY: 0.2, ZZ: 0.2}
	result, err := EvaluateAdmissibility(object, participant, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	want := FailureFrameMismatch | FailureLowConfidence | FailureStale |
		FailureFloorMismatch | FailureUncertainty
	if result.Admissible || result.Failures != want {
		t.Fatalf("expected failures %b, got %#v", want, result)
	}
}

func TestAdmissibilityRejectsFutureAndExcessDistance(t *testing.T) {
	object, participant, policy, now := admissibilityFixture(t)
	object.ObservedAt = now.Add(2 * time.Second)
	participant.Position = Vector3{X: math.MaxFloat64, Y: -math.MaxFloat64, Z: 0}
	result, err := EvaluateAdmissibility(object, participant, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Failures.Has(FailureFuture) || !result.Failures.Has(FailureProximity) {
		t.Fatalf("expected future and proximity failures, got %#v", result)
	}
}

func TestAdmissibilityRejectsMutatedInvalidEstimate(t *testing.T) {
	object, participant, policy, now := admissibilityFixture(t)
	object.Position.X = math.NaN()
	if _, err := EvaluateAdmissibility(object, participant, policy, now); !errors.Is(err, ErrNonFiniteValue) {
		t.Fatalf("expected mutated estimate rejection, got %v", err)
	}
}

func TestAdmissibilityPolicyRejectsUnsafeBounds(t *testing.T) {
	object, participant, policy, now := admissibilityFixture(t)
	policy.MaxDistance = math.Inf(1)
	if _, err := EvaluateAdmissibility(object, participant, policy, now); !errors.Is(err, ErrInvalidAdmissibilityPolicy) {
		t.Fatalf("expected invalid policy, got %v", err)
	}
}
