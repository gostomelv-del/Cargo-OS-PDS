package spatial

import (
	"errors"
	"math"
	"testing"
	"time"
)

func validEstimateInput() EstimateInput {
	return EstimateInput{
		Frame: "warehouse-a/map-v2", Position: Vector3{X: 1.5, Y: -2, Z: 0.8}, Floor: 3,
		Covariance: Covariance3{XX: 0.04, XY: 0.01, YY: 0.09, ZZ: 0.01},
		Confidence: 0.97, ObservedAt: time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC),
		ProfileID: "indoor-fusion", ProfileVersion: "v4", CalibrationVersion: "site-a-2026-08",
	}
}

func TestNewEstimateCreatesCanonicalBoundedSpatialState(t *testing.T) {
	estimate, err := NewEstimate(validEstimateInput())
	if err != nil {
		t.Fatal(err)
	}
	if estimate.Frame != "warehouse-a/map-v2" || estimate.Floor != 3 || estimate.Confidence != 0.97 {
		t.Fatalf("unexpected estimate: %#v", estimate)
	}
	trace, err := estimate.Covariance.Trace()
	if err != nil || math.Abs(trace-0.14) > 1e-12 {
		t.Fatalf("unexpected covariance trace: %v (%v)", trace, err)
	}
}

func TestEstimateRejectsNonFiniteNumbers(t *testing.T) {
	cases := []struct {
		name string
		edit func(*EstimateInput)
	}{
		{"position NaN", func(input *EstimateInput) { input.Position.X = math.NaN() }},
		{"position infinity", func(input *EstimateInput) { input.Position.Z = math.Inf(1) }},
		{"covariance NaN", func(input *EstimateInput) { input.Covariance.XY = math.NaN() }},
		{"confidence infinity", func(input *EstimateInput) { input.Confidence = math.Inf(-1) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			input := validEstimateInput()
			test.edit(&input)
			if _, err := NewEstimate(input); !errors.Is(err, ErrNonFiniteValue) {
				t.Fatalf("expected non-finite rejection, got %v", err)
			}
		})
	}
}

func TestCovarianceRejectsNonPositiveSemidefiniteMatrices(t *testing.T) {
	cases := []Covariance3{
		{XX: -0.1, YY: 1, ZZ: 1},
		{XX: -1e-15, YY: 1, ZZ: 1},
		{XX: 1, XY: 2, YY: 1, ZZ: 1},
		{XX: 1, XY: -0.9, XZ: -0.9, YY: 1, YZ: -0.9, ZZ: 1},
	}
	for _, covariance := range cases {
		if err := covariance.Validate(); !errors.Is(err, ErrInvalidCovariance) {
			t.Fatalf("expected PSD rejection for %#v, got %v", covariance, err)
		}
	}
}

func TestCovarianceValidationAvoidsOverflow(t *testing.T) {
	covariance := Covariance3{XX: math.MaxFloat64, YY: math.MaxFloat64, ZZ: math.MaxFloat64}
	if err := covariance.Validate(); err != nil {
		t.Fatalf("large finite diagonal covariance was rejected: %v", err)
	}
	if _, err := covariance.Trace(); !errors.Is(err, ErrNonFiniteValue) {
		t.Fatalf("expected overflowing trace rejection, got %v", err)
	}
}

func TestEstimateRequiresDeclaredVersionsAndBounds(t *testing.T) {
	cases := []struct {
		name string
		edit func(*EstimateInput)
		want error
	}{
		{"frame", func(input *EstimateInput) { input.Frame = "" }, ErrFrameRequired},
		{"low confidence", func(input *EstimateInput) { input.Confidence = -0.01 }, ErrConfidenceRange},
		{"high confidence", func(input *EstimateInput) { input.Confidence = 1.01 }, ErrConfidenceRange},
		{"time", func(input *EstimateInput) { input.ObservedAt = time.Time{} }, ErrObservedAtRequired},
		{"profile", func(input *EstimateInput) { input.ProfileVersion = " " }, ErrProfileRequired},
		{"calibration", func(input *EstimateInput) { input.CalibrationVersion = "" }, ErrCalibrationRequired},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			input := validEstimateInput()
			test.edit(&input)
			if _, err := NewEstimate(input); !errors.Is(err, test.want) {
				t.Fatalf("expected %v, got %v", test.want, err)
			}
		})
	}
}
