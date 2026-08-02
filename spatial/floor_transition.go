package spatial

import (
	"errors"
	"math"
	"time"
)

var ErrInvalidFloorTransitionPolicy = errors.New("spatial: invalid floor transition policy")

const MaxFloorStep uint32 = 100

type FloorFailure uint32

const FloorFailureNone FloorFailure = 0

const (
	FloorFailureFrame FloorFailure = 1 << iota
	FloorFailureProfile
	FloorFailureConfidence
	FloorFailureTimeOrder
	FloorFailureStale
	FloorFailureFuture
	FloorFailureStep
	FloorFailureDirection
	FloorFailureHeight
)

func (failure FloorFailure) Has(flag FloorFailure) bool { return failure&flag != 0 }

type FloorTransitionPolicy struct {
	MinConfidence         float64
	MaxTransitionDuration time.Duration
	MaxAge                time.Duration
	FutureTolerance       time.Duration
	MaxStep               uint32
	MinHeightPerFloor     float64
	MaxHeightPerFloor     float64
	StationaryTolerance   float64
}

func (policy FloorTransitionPolicy) Validate() error {
	if !finite(policy.MinConfidence) || policy.MinConfidence < 0 || policy.MinConfidence > 1 ||
		policy.MaxTransitionDuration <= 0 || policy.MaxAge <= 0 || policy.FutureTolerance < 0 ||
		policy.MaxStep == 0 || policy.MaxStep > MaxFloorStep ||
		!finite(policy.MinHeightPerFloor) || policy.MinHeightPerFloor <= 0 ||
		!finite(policy.MaxHeightPerFloor) || policy.MaxHeightPerFloor < policy.MinHeightPerFloor ||
		policy.MaxHeightPerFloor > math.MaxFloat64/float64(policy.MaxStep) ||
		!finite(policy.StationaryTolerance) || policy.StationaryTolerance < 0 {
		return ErrInvalidFloorTransitionPolicy
	}
	return nil
}

type FloorTransitionResult struct {
	Consistent    bool
	Failures      FloorFailure
	FloorDelta    int64
	VerticalDelta float64
	Elapsed       time.Duration
	Age           time.Duration
}

func EvaluateFloorTransition(
	previous Estimate,
	current Estimate,
	policy FloorTransitionPolicy,
	now time.Time,
) (FloorTransitionResult, error) {
	if err := previous.Validate(); err != nil {
		return FloorTransitionResult{}, err
	}
	if err := current.Validate(); err != nil {
		return FloorTransitionResult{}, err
	}
	if err := policy.Validate(); err != nil {
		return FloorTransitionResult{}, err
	}
	if now.IsZero() {
		return FloorTransitionResult{}, ErrEvaluationTimeRequired
	}
	now = now.UTC()
	result := FloorTransitionResult{
		FloorDelta:    int64(current.Floor) - int64(previous.Floor),
		VerticalDelta: current.Position.Z - previous.Position.Z,
		Elapsed:       current.ObservedAt.Sub(previous.ObservedAt),
		Age:           now.Sub(current.ObservedAt),
	}
	if previous.Frame != current.Frame {
		result.Failures |= FloorFailureFrame
	}
	if previous.ProfileID != current.ProfileID || previous.ProfileVersion != current.ProfileVersion ||
		previous.CalibrationVersion != current.CalibrationVersion {
		result.Failures |= FloorFailureProfile
	}
	if previous.Confidence < policy.MinConfidence || current.Confidence < policy.MinConfidence {
		result.Failures |= FloorFailureConfidence
	}
	if result.Elapsed <= 0 || result.Elapsed > policy.MaxTransitionDuration {
		result.Failures |= FloorFailureTimeOrder
	}
	if result.Age > policy.MaxAge {
		result.Failures |= FloorFailureStale
	}
	if result.Age < -policy.FutureTolerance {
		result.Failures |= FloorFailureFuture
	}
	steps := absFloorDelta(result.FloorDelta)
	if steps > uint64(policy.MaxStep) {
		result.Failures |= FloorFailureStep
	}
	if !finite(result.VerticalDelta) {
		result.Failures |= FloorFailureHeight
	} else if result.FloorDelta == 0 {
		if math.Abs(result.VerticalDelta) > policy.StationaryTolerance {
			result.Failures |= FloorFailureHeight
		}
	} else {
		if (result.FloorDelta > 0 && result.VerticalDelta <= 0) ||
			(result.FloorDelta < 0 && result.VerticalDelta >= 0) {
			result.Failures |= FloorFailureDirection
		}
		height := math.Abs(result.VerticalDelta)
		minimum := float64(steps) * policy.MinHeightPerFloor
		maximum := float64(steps) * policy.MaxHeightPerFloor
		if height < minimum || height > maximum {
			result.Failures |= FloorFailureHeight
		}
	}
	result.Consistent = result.Failures == FloorFailureNone
	return result, nil
}

func absFloorDelta(delta int64) uint64 {
	if delta < 0 {
		return uint64(-delta)
	}
	return uint64(delta)
}
