package audit

import (
	"errors"
	"testing"
	"time"
)

func TestChainBindsPreviousAndRecordRoots(t *testing.T) {
	at := time.Date(2026, 8, 2, 12, 0, 0, 123456789, time.UTC)
	first, err := NewEntry(1, RecordEstimator, [32]byte{}, [32]byte{1}, at)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewEntry(2, RecordResponsibilityHandover, first.Root, [32]byte{2}, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if second.PreviousRoot != first.Root || second.Root == first.Root {
		t.Fatalf("chain binding was lost: %#v", second)
	}
	if !first.OccurredAt.Equal(at.Truncate(time.Microsecond)) {
		t.Fatalf("time was not normalized: %v", first.OccurredAt)
	}
}

func TestChainRejectsForkShapeAndTampering(t *testing.T) {
	at := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	if _, err := NewEntry(1, RecordEstimator, [32]byte{9}, [32]byte{1}, at); !errors.Is(err, ErrSequenceInvalid) {
		t.Fatalf("expected genesis previous-root rejection, got %v", err)
	}
	entry, err := NewEntry(2, RecordEstimator, [32]byte{9}, [32]byte{1}, at)
	if err != nil {
		t.Fatal(err)
	}
	entry.RecordRoot[0] = 7
	if err = entry.Validate(); !errors.Is(err, ErrEntryNotCanonical) {
		t.Fatalf("expected tamper rejection, got %v", err)
	}
}
