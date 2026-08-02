package estimator

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"cargoos/responsibility"
	"cargoos/spatial"
)

var (
	ErrObjectRequired      = errors.New("estimator: physical object is required")
	ErrObservationRequired = errors.New("estimator: observation identity and digest are required")
	ErrSequenceInvalid     = errors.New("estimator: sequence and prior state are inconsistent")
	ErrObservationTime     = errors.New("estimator: observation times are invalid")
	ErrTargetFrameRequired = errors.New("estimator: target frame is required")
	ErrProfileRequired     = errors.New("estimator: profile and calibration versions are required")
	ErrPriorStateInvalid   = errors.New("estimator: prior state is invalid")
	ErrPortRequired        = errors.New("estimator: port is required")
	ErrOutputBinding       = errors.New("estimator: output does not match request")
	ErrCompletionTime      = errors.New("estimator: completion time is invalid")
)

type Request struct {
	ObjectID           responsibility.PhysicalObjectID
	Sequence           uint64
	ObservationID      uuid.UUID
	ObservationDigest  [32]byte
	ObservedAt         time.Time
	ReceivedAt         time.Time
	TargetFrame        spatial.FrameID
	ProfileID          string
	ProfileVersion     string
	CalibrationVersion string
	HasPrior           bool
	Prior              spatial.Estimate
}

func (request Request) Validate() error {
	objectID, err := responsibility.NewPhysicalObjectID(request.ObjectID.String())
	if err != nil || objectID != request.ObjectID {
		return ErrObjectRequired
	}
	if request.ObservationID == uuid.Nil || request.ObservationDigest == ([32]byte{}) {
		return ErrObservationRequired
	}
	if request.ObservedAt.IsZero() || request.ReceivedAt.IsZero() || request.ReceivedAt.Before(request.ObservedAt) {
		return ErrObservationTime
	}
	frame, err := spatial.NewFrameID(request.TargetFrame.String())
	if err != nil || frame != request.TargetFrame {
		return ErrTargetFrameRequired
	}
	if strings.TrimSpace(request.ProfileID) == "" || request.ProfileID != strings.TrimSpace(request.ProfileID) ||
		strings.TrimSpace(request.ProfileVersion) == "" || request.ProfileVersion != strings.TrimSpace(request.ProfileVersion) ||
		strings.TrimSpace(request.CalibrationVersion) == "" || request.CalibrationVersion != strings.TrimSpace(request.CalibrationVersion) {
		return ErrProfileRequired
	}
	if request.Sequence == 0 || request.HasPrior != (request.Sequence > 1) {
		return ErrSequenceInvalid
	}
	if !request.HasPrior {
		if request.Prior != (spatial.Estimate{}) {
			return ErrSequenceInvalid
		}
		return nil
	}
	if err = request.Prior.Validate(); err != nil || !request.Prior.ObservedAt.Before(request.ObservedAt) ||
		request.Prior.Frame != request.TargetFrame || request.Prior.ProfileID != request.ProfileID ||
		request.Prior.ProfileVersion != request.ProfileVersion ||
		request.Prior.CalibrationVersion != request.CalibrationVersion {
		return ErrPriorStateInvalid
	}
	return nil
}

type Port interface {
	Estimate(context.Context, Request) (spatial.Estimate, error)
}

type ReplayMetadata struct {
	ObjectID           responsibility.PhysicalObjectID
	Sequence           uint64
	ObservationID      uuid.UUID
	ObservationDigest  [32]byte
	ObservedAt         time.Time
	ReceivedAt         time.Time
	TargetFrame        spatial.FrameID
	ProfileID          string
	ProfileVersion     string
	CalibrationVersion string
	HasPrior           bool
	Prior              spatial.Estimate
	CompletedAt        time.Time
}

type Result struct {
	Estimate spatial.Estimate
	Replay   ReplayMetadata
}

func Execute(
	ctx context.Context,
	port Port,
	request Request,
	completedAt time.Time,
) (Result, error) {
	if port == nil {
		return Result{}, ErrPortRequired
	}
	if err := request.Validate(); err != nil {
		return Result{}, err
	}
	if completedAt.IsZero() || completedAt.Before(request.ReceivedAt) {
		return Result{}, ErrCompletionTime
	}
	estimate, err := port.Estimate(ctx, request)
	if err != nil {
		return Result{}, err
	}
	if err = estimate.Validate(); err != nil {
		return Result{}, err
	}
	if estimate.Frame != request.TargetFrame || estimate.ObservedAt != request.ObservedAt.UTC() ||
		estimate.ProfileID != request.ProfileID || estimate.ProfileVersion != request.ProfileVersion ||
		estimate.CalibrationVersion != request.CalibrationVersion {
		return Result{}, ErrOutputBinding
	}
	metadata := ReplayMetadata{
		ObjectID: request.ObjectID, Sequence: request.Sequence,
		ObservationID: request.ObservationID, ObservationDigest: request.ObservationDigest,
		ObservedAt: request.ObservedAt.UTC(), ReceivedAt: request.ReceivedAt.UTC(),
		TargetFrame: request.TargetFrame, ProfileID: request.ProfileID,
		ProfileVersion: request.ProfileVersion, CalibrationVersion: request.CalibrationVersion,
		HasPrior: request.HasPrior, CompletedAt: completedAt.UTC(),
	}
	if request.HasPrior {
		metadata.Prior = request.Prior
	}
	return Result{Estimate: estimate, Replay: metadata}, nil
}
