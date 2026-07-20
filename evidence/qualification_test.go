package evidence

import (
	"errors"
	"testing"
	"time"
)

func testQualifier(t *testing.T) (*Qualifier, time.Time) {
	t.Helper()
	minimum := 0.9
	qualifier, err := NewQualifier(QualificationPolicy{
		Version:                   "qualification.v1",
		TrustedSources:            map[string]bool{"scale-17": true},
		AllowedTypes:              map[Type]bool{TypeWeight: true},
		AllowedAcquisitionMethods: map[string]bool{"MQTT": true},
		MaxAge:                    time.Minute, FutureTolerance: time.Second,
		RequireConfidence: true, MinimumConfidence: &minimum,
		RequiredProvenance:    []string{"calibration_id"},
		RequiredPayloadFields: []string{"unit", "value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return qualifier, time.Date(2026, 7, 20, 12, 0, 30, 0, time.UTC)
}

func qualifiedObject(t *testing.T) *Object {
	t.Helper()
	input := validInput()
	input.Provenance["calibration_id"] = "cal-2026-07"
	object, err := NewObject(input)
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func TestQualifierAcceptsEvidenceMatchingPolicy(t *testing.T) {
	qualifier, now := testQualifier(t)
	result, err := qualifier.Qualify(qualifiedObject(t), now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != QualificationQualified || len(result.Reasons) != 0 || result.PolicyVersion != "qualification.v1" {
		t.Fatalf("unexpected qualification: %#v", result)
	}
}

func TestQualifierRejectsWithDeterministicReasons(t *testing.T) {
	qualifier, now := testQualifier(t)
	input := validInput()
	input.SourceID = "unknown-scale"
	input.EvidenceType = TypePosition
	input.ObservedAt = now.Add(-2 * time.Minute)
	input.ReceivedAt = input.ObservedAt.Add(time.Second)
	low := 0.5
	input.Confidence = &low
	input.Payload = []byte(`{"value":25}`)
	input.AcquisitionMethod = "HTTP"
	object, err := NewObject(input)
	if err != nil {
		t.Fatal(err)
	}
	result, err := qualifier.Qualify(object, now)
	if err != nil {
		t.Fatal(err)
	}
	want := []QualificationReasonCode{
		ReasonSourceUntrusted, ReasonTypeNotAllowed, ReasonEvidenceExpired,
		ReasonConfidenceLow, ReasonProvenanceMissing, ReasonPayloadFieldMissing,
		ReasonAcquisitionDenied,
	}
	if result.Status != QualificationRejected || len(result.Reasons) != len(want) {
		t.Fatalf("unexpected rejection: %#v", result)
	}
	for index := range want {
		if result.Reasons[index].Code != want[index] {
			t.Fatalf("reason %d: got %s, want %s", index, result.Reasons[index].Code, want[index])
		}
	}
}

func TestQualifierReportsUnavailableEvidence(t *testing.T) {
	qualifier, now := testQualifier(t)
	result, err := qualifier.Qualify(nil, now)
	if err != nil || result.Status != QualificationUnavailable || result.Reasons[0].Code != ReasonEvidenceUnavailable {
		t.Fatalf("unexpected unavailable result: %#v, %v", result, err)
	}
}

func TestQualifierRejectsFutureEvidence(t *testing.T) {
	qualifier, now := testQualifier(t)
	input := validInput()
	input.ObservedAt = now.Add(2 * time.Second)
	input.ReceivedAt = input.ObservedAt
	input.Provenance["calibration_id"] = "cal-2026-07"
	object, err := NewObject(input)
	if err != nil {
		t.Fatal(err)
	}
	result, err := qualifier.Qualify(object, now)
	if err != nil || result.Status != QualificationRejected || result.Reasons[0].Code != ReasonTimestampFuture {
		t.Fatalf("unexpected future result: %#v, %v", result, err)
	}
}

func TestQualificationPolicyValidation(t *testing.T) {
	if _, err := NewQualifier(QualificationPolicy{}); !errors.Is(err, ErrQualificationPolicyVersionRequired) {
		t.Fatalf("expected policy version error, got %v", err)
	}
	if _, err := NewQualifier(QualificationPolicy{Version: "v1", MaxAge: -time.Second}); !errors.Is(err, ErrInvalidQualificationMaxAge) {
		t.Fatalf("expected max age error, got %v", err)
	}
	invalid := 1.1
	if _, err := NewQualifier(QualificationPolicy{Version: "v1", MinimumConfidence: &invalid}); !errors.Is(err, ErrInvalidQualificationConfidence) {
		t.Fatalf("expected confidence error, got %v", err)
	}
	qualifier, _ := NewQualifier(QualificationPolicy{Version: "v1"})
	if _, err := qualifier.Qualify(nil, time.Time{}); !errors.Is(err, ErrQualificationTimeRequired) {
		t.Fatalf("expected evaluation time error, got %v", err)
	}
}
