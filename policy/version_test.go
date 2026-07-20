package policy

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func policyInput(version string, from time.Time, until *time.Time) Input {
	return Input{
		PolicyID: "cargo-transfer", Version: version, SchemaVersion: "policy.v1",
		EffectiveFrom: from, EffectiveUntil: until,
		RequiredRuleIDs: []string{"weight", "support-sequence"},
		Document:        json.RawMessage(`{ "threshold": 25.00, "mode": "strict" }`),
	}
}

func TestVersionCanonicalHashIsStable(t *testing.T) {
	base := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	first, err := NewVersion(policyInput("1.0.0", base, nil))
	if err != nil {
		t.Fatal(err)
	}
	secondInput := policyInput("1.0.0", base, nil)
	secondInput.Document = json.RawMessage(`{"mode":"strict","threshold":25.00}`)
	second, err := NewVersion(secondInput)
	if err != nil {
		t.Fatal(err)
	}
	if first.Snapshot().Hash != second.Snapshot().Hash || string(first.Snapshot().Document) != `{"mode":"strict","threshold":25.00}` {
		t.Fatalf("canonical policy identity changed: %#v %#v", first.Snapshot(), second.Snapshot())
	}
	if _, err = Rehydrate(first.Snapshot()); err != nil {
		t.Fatal(err)
	}
}

func TestVersionRejectsTamperingAndInvalidRules(t *testing.T) {
	base := time.Now().UTC()
	version, _ := NewVersion(policyInput("1.0.0", base, nil))
	snapshot := version.Snapshot()
	snapshot.Document = json.RawMessage(`{"mode":"relaxed","threshold":25}`)
	if _, err := Rehydrate(snapshot); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("expected hash mismatch, got %v", err)
	}
	input := policyInput("1.0.0", base, nil)
	input.RequiredRuleIDs = []string{"weight", "weight"}
	if _, err := NewVersion(input); !errors.Is(err, ErrDuplicateRequiredRule) {
		t.Fatalf("expected duplicate rule error, got %v", err)
	}
}

func TestRegistryResolvesHalfOpenEffectivePeriods(t *testing.T) {
	base := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	boundary := base.Add(24 * time.Hour)
	first, _ := NewVersion(policyInput("1.0.0", base, &boundary))
	second, _ := NewVersion(policyInput("2.0.0", boundary, nil))
	registry := NewRegistry()
	if err := registry.Add(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := registry.Add(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	resolved, err := registry.Resolve(context.Background(), "cargo-transfer", boundary)
	if err != nil || resolved.Snapshot().Version != "2.0.0" {
		t.Fatalf("wrong boundary version: %#v, %v", resolved, err)
	}
	if _, err = registry.Resolve(context.Background(), "cargo-transfer", base.Add(-time.Second)); !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestRegistryRejectsOverlappingVersions(t *testing.T) {
	base := time.Now().UTC()
	until := base.Add(2 * time.Hour)
	first, _ := NewVersion(policyInput("1.0.0", base, &until))
	second, _ := NewVersion(policyInput("2.0.0", base.Add(time.Hour), nil))
	registry := NewRegistry()
	_ = registry.Add(context.Background(), first)
	if err := registry.Add(context.Background(), second); !errors.Is(err, ErrEffectiveOverlap) {
		t.Fatalf("expected overlap error, got %v", err)
	}
	if err := registry.Add(context.Background(), first); err != nil {
		t.Fatalf("identical version was not idempotent: %v", err)
	}
}
