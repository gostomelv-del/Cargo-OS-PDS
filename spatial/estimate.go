package spatial

import (
	"errors"
	"math"
	"strings"
	"time"
)

var (
	ErrFrameRequired       = errors.New("spatial: coordinate frame is required")
	ErrNonFiniteValue      = errors.New("spatial: value must be finite")
	ErrInvalidCovariance   = errors.New("spatial: covariance must be positive semidefinite")
	ErrConfidenceRange     = errors.New("spatial: confidence must be in [0,1]")
	ErrObservedAtRequired  = errors.New("spatial: observation time is required")
	ErrProfileRequired     = errors.New("spatial: estimator profile and version are required")
	ErrCalibrationRequired = errors.New("spatial: calibration version is required")
)

type FrameID string

func NewFrameID(value string) (FrameID, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ErrFrameRequired
	}
	return FrameID(value), nil
}

func (id FrameID) String() string { return string(id) }

type Vector3 struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
	Z float64 `json:"z"`
}

func (vector Vector3) Validate() error {
	if !finite(vector.X) || !finite(vector.Y) || !finite(vector.Z) {
		return ErrNonFiniteValue
	}
	return nil
}

// Covariance3 stores the six independent entries of a symmetric 3x3 matrix.
// The compact value representation avoids heap-backed rows and symmetry drift.
type Covariance3 struct {
	XX float64 `json:"xx"`
	XY float64 `json:"xy"`
	XZ float64 `json:"xz"`
	YY float64 `json:"yy"`
	YZ float64 `json:"yz"`
	ZZ float64 `json:"zz"`
}

func (covariance Covariance3) Validate() error {
	if !finite(covariance.XX) || !finite(covariance.XY) || !finite(covariance.XZ) ||
		!finite(covariance.YY) || !finite(covariance.YZ) || !finite(covariance.ZZ) {
		return ErrNonFiniteValue
	}
	scale := math.Max(
		math.Max(math.Abs(covariance.XX), math.Abs(covariance.XY)),
		math.Max(
			math.Max(math.Abs(covariance.XZ), math.Abs(covariance.YY)),
			math.Max(math.Abs(covariance.YZ), math.Abs(covariance.ZZ)),
		),
	)
	if scale == 0 {
		return nil
	}
	xx, xy, xz := covariance.XX/scale, covariance.XY/scale, covariance.XZ/scale
	yy, yz, zz := covariance.YY/scale, covariance.YZ/scale, covariance.ZZ/scale
	const tolerance = 1e-12
	if covariance.XX < 0 || covariance.YY < 0 || covariance.ZZ < 0 ||
		xx*yy-xy*xy < -tolerance || xx*zz-xz*xz < -tolerance ||
		yy*zz-yz*yz < -tolerance {
		return ErrInvalidCovariance
	}
	determinant := xx*(yy*zz-yz*yz) - xy*(xy*zz-yz*xz) + xz*(xy*yz-yy*xz)
	if determinant < -tolerance {
		return ErrInvalidCovariance
	}
	return nil
}

func (covariance Covariance3) Trace() (float64, error) {
	trace := covariance.XX + covariance.YY + covariance.ZZ
	if !finite(trace) {
		return 0, ErrNonFiniteValue
	}
	return trace, nil
}

type EstimateInput struct {
	Frame              FrameID
	Position           Vector3
	Floor              int32
	Covariance         Covariance3
	Confidence         float64
	ObservedAt         time.Time
	ProfileID          string
	ProfileVersion     string
	CalibrationVersion string
}

type Estimate struct {
	Frame              FrameID     `json:"frame"`
	Position           Vector3     `json:"position"`
	Floor              int32       `json:"floor"`
	Covariance         Covariance3 `json:"covariance"`
	Confidence         float64     `json:"confidence"`
	ObservedAt         time.Time   `json:"observed_at"`
	ProfileID          string      `json:"profile_id"`
	ProfileVersion     string      `json:"profile_version"`
	CalibrationVersion string      `json:"calibration_version"`
}

func NewEstimate(input EstimateInput) (Estimate, error) {
	frame, err := NewFrameID(input.Frame.String())
	if err != nil || frame != input.Frame {
		return Estimate{}, ErrFrameRequired
	}
	if err = input.Position.Validate(); err != nil {
		return Estimate{}, err
	}
	if err = input.Covariance.Validate(); err != nil {
		return Estimate{}, err
	}
	if !finite(input.Confidence) {
		return Estimate{}, ErrNonFiniteValue
	}
	if input.Confidence < 0 || input.Confidence > 1 {
		return Estimate{}, ErrConfidenceRange
	}
	if input.ObservedAt.IsZero() {
		return Estimate{}, ErrObservedAtRequired
	}
	input.ProfileID = strings.TrimSpace(input.ProfileID)
	input.ProfileVersion = strings.TrimSpace(input.ProfileVersion)
	if input.ProfileID == "" || input.ProfileVersion == "" {
		return Estimate{}, ErrProfileRequired
	}
	input.CalibrationVersion = strings.TrimSpace(input.CalibrationVersion)
	if input.CalibrationVersion == "" {
		return Estimate{}, ErrCalibrationRequired
	}
	return Estimate{
		Frame: frame, Position: input.Position, Floor: input.Floor,
		Covariance: input.Covariance, Confidence: input.Confidence,
		ObservedAt: input.ObservedAt.UTC(), ProfileID: input.ProfileID,
		ProfileVersion: input.ProfileVersion, CalibrationVersion: input.CalibrationVersion,
	}, nil
}

func finite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}
