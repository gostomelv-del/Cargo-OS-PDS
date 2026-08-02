package spatial

import (
	"errors"
	"math"
	"time"
)

var (
	ErrInvalidAdmissibilityPolicy = errors.New("spatial: invalid admissibility policy")
	ErrEvaluationTimeRequired     = errors.New("spatial: evaluation time is required")
)

type Failure uint32

const FailureNone Failure = 0

const (
	FailureFrameMismatch Failure = 1 << iota
	FailureLowConfidence
	FailureStale
	FailureFuture
	FailureProximity
	FailureFloorMismatch
	FailureUncertainty
)

func (failure Failure) Has(flag Failure) bool { return failure&flag != 0 }

type AdmissibilityPolicy struct {
	MinConfidence   float64
	MaxAge          time.Duration
	FutureTolerance time.Duration
	MaxDistance     float64
	MaxTrace        float64
}

func (policy AdmissibilityPolicy) Validate() error {
	if !finite(policy.MinConfidence) || policy.MinConfidence < 0 || policy.MinConfidence > 1 ||
		policy.MaxAge <= 0 || policy.FutureTolerance < 0 ||
		!finite(policy.MaxDistance) || policy.MaxDistance <= 0 ||
		!finite(policy.MaxTrace) || policy.MaxTrace <= 0 {
		return ErrInvalidAdmissibilityPolicy
	}
	return nil
}

type AdmissibilityResult struct {
	Admissible     bool
	Failures       Failure
	Distance       float64
	ObjectAge      time.Duration
	ParticipantAge time.Duration
}

func EvaluateAdmissibility(
	object Estimate,
	participant Estimate,
	policy AdmissibilityPolicy,
	now time.Time,
) (AdmissibilityResult, error) {
	if err := object.Validate(); err != nil {
		return AdmissibilityResult{}, err
	}
	if err := participant.Validate(); err != nil {
		return AdmissibilityResult{}, err
	}
	if err := policy.Validate(); err != nil {
		return AdmissibilityResult{}, err
	}
	if now.IsZero() {
		return AdmissibilityResult{}, ErrEvaluationTimeRequired
	}
	now = now.UTC()
	result := AdmissibilityResult{
		ObjectAge: now.Sub(object.ObservedAt), ParticipantAge: now.Sub(participant.ObservedAt),
	}
	if object.Frame != participant.Frame {
		result.Failures |= FailureFrameMismatch
	} else {
		dx := object.Position.X - participant.Position.X
		dy := object.Position.Y - participant.Position.Y
		dz := object.Position.Z - participant.Position.Z
		result.Distance = math.Hypot(math.Hypot(dx, dy), dz)
		if !finite(result.Distance) || result.Distance > policy.MaxDistance {
			result.Failures |= FailureProximity
		}
	}
	if object.Confidence < policy.MinConfidence || participant.Confidence < policy.MinConfidence {
		result.Failures |= FailureLowConfidence
	}
	if result.ObjectAge > policy.MaxAge || result.ParticipantAge > policy.MaxAge {
		result.Failures |= FailureStale
	}
	if result.ObjectAge < -policy.FutureTolerance || result.ParticipantAge < -policy.FutureTolerance {
		result.Failures |= FailureFuture
	}
	if object.Floor != participant.Floor {
		result.Failures |= FailureFloorMismatch
	}
	objectTrace, objectTraceErr := object.Covariance.Trace()
	participantTrace, participantTraceErr := participant.Covariance.Trace()
	if objectTraceErr != nil || participantTraceErr != nil ||
		objectTrace > policy.MaxTrace || participantTrace > policy.MaxTrace {
		result.Failures |= FailureUncertainty
	}
	result.Admissible = result.Failures == FailureNone
	return result, nil
}
