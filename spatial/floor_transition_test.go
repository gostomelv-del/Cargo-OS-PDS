package spatial

import (
	"errors"
	"math"
	"testing"
	"time"
)

func floorTransitionFixture(t *testing.T) (Estimate, Estimate, FloorTransitionPolicy, time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 2, 12, 10, 0, 0, time.UTC)
	previousInput := validEstimateInput()
	previousInput.Floor = 2
	previousInput.Position.Z = 6
	previousInput.ObservedAt = now.Add(-2 * time.Minute)
	currentInput := previousInput
	currentInput.Floor = 3
	currentInput.Position.Z = 9
	currentInput.ObservedAt = now.Add(-time.Second)
	previous, err := NewEstimate(previousInput)
	if err != nil {
		t.Fatal(err)
	}
	current, err := NewEstimate(currentInput)
	if err != nil {
		t.Fatal(err)
	}
	policy := FloorTransitionPolicy{
		MinConfidence: 0.9, MaxTransitionDuration: 3 * time.Minute,
		MaxAge: 5 * time.Second, FutureTolerance: time.Second, MaxStep: 2,
		MinHeightPerFloor: 2.5, MaxHeightPerFloor: 3.5, StationaryTolerance: 0.5,
	}
	return previous, current, policy, now
}

func TestFloorTransitionAcceptsCalibratedBoundary(t *testing.T) {
	previous, current, policy, now := floorTransitionFixture(t)
	current.Position.Z = previous.Position.Z + policy.MinHeightPerFloor
	result, err := EvaluateFloorTransition(previous, current, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Consistent || result.Failures != FloorFailureNone || result.FloorDelta != 1 {
		t.Fatalf("expected consistent transition, got %#v", result)
	}
}

func TestFloorTransitionCollectsDeterministicFailures(t *testing.T) {
	previous, current, policy, now := floorTransitionFixture(t)
	current.Frame = "other/frame"
	current.ProfileVersion = "v5"
	current.Confidence = 0.5
	current.Floor = 8
	current.Position.Z = 5
	current.ObservedAt = previous.ObservedAt
	result, err := EvaluateFloorTransition(previous, current, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	want := FloorFailureFrame | FloorFailureProfile | FloorFailureConfidence |
		FloorFailureTimeOrder | FloorFailureStale | FloorFailureStep |
		FloorFailureDirection | FloorFailureHeight
	if result.Consistent || result.Failures != want {
		t.Fatalf("expected failures %b, got %#v", want, result)
	}
}

func TestStationaryFloorRejectsExcessVerticalMotion(t *testing.T) {
	previous, current, policy, now := floorTransitionFixture(t)
	current.Floor = previous.Floor
	current.Position.Z = previous.Position.Z + policy.StationaryTolerance + 0.01
	result, err := EvaluateFloorTransition(previous, current, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Failures.Has(FloorFailureHeight) || result.Failures.Has(FloorFailureDirection) {
		t.Fatalf("unexpected stationary-floor result: %#v", result)
	}
}

func TestFloorTransitionRejectsOverflowingVerticalDelta(t *testing.T) {
	previous, current, policy, now := floorTransitionFixture(t)
	previous.Position.Z = -math.MaxFloat64
	current.Position.Z = math.MaxFloat64
	result, err := EvaluateFloorTransition(previous, current, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Failures.Has(FloorFailureHeight) {
		t.Fatalf("overflowing height was accepted: %#v", result)
	}
}

func TestFloorTransitionPolicyIsBounded(t *testing.T) {
	previous, current, policy, now := floorTransitionFixture(t)
	policy.MaxStep = MaxFloorStep + 1
	if _, err := EvaluateFloorTransition(previous, current, policy, now); !errors.Is(err, ErrInvalidFloorTransitionPolicy) {
		t.Fatalf("expected bounded-step rejection, got %v", err)
	}
}

func TestFloorTransitionPolicyRejectsHeightOverflow(t *testing.T) {
	previous, current, policy, now := floorTransitionFixture(t)
	policy.MaxHeightPerFloor = math.MaxFloat64
	if _, err := EvaluateFloorTransition(previous, current, policy, now); !errors.Is(err, ErrInvalidFloorTransitionPolicy) {
		t.Fatalf("expected height-overflow rejection, got %v", err)
	}
}
