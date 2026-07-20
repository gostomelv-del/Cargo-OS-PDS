package policy

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestActivateRequiresMatchingPriorApproval(t *testing.T) {
	at := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	version, _ := NewVersion(policyInput("1.0.0", at, nil))
	verified := verifiedForTest(t, version, at.Add(-time.Minute))
	snapshot := version.Snapshot()
	approval := ApprovalRecord{
		PolicyID: snapshot.PolicyID, Version: snapshot.Version, PolicyHash: snapshot.Hash,
		ApprovedBy: "policy-review-board", ApprovedAt: at.Add(-time.Second),
	}
	if _, err := Activate(verified, approval, at); err != nil {
		t.Fatal(err)
	}
	approval.PolicyHash = "sha256:wrong"
	if _, err := Activate(verified, approval, at); !errors.Is(err, ErrApprovalIdentityMismatch) {
		t.Fatalf("expected approval identity rejection, got %v", err)
	}
	approval.PolicyHash = snapshot.Hash
	approval.ApprovedAt = at.Add(time.Second)
	if _, err := Activate(verified, approval, at); !errors.Is(err, ErrApprovalAfterActivation) {
		t.Fatalf("expected late approval rejection, got %v", err)
	}
}

func TestRegistryLifecycleClosesResolutionFailClosed(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	version, _ := NewVersion(policyInput("1.0.0", at, nil))
	registry := NewRegistry()
	if err := registry.Add(ctx, activatedForTest(t, version, at)); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Resolve(ctx, "cargo-transfer", at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := registry.Suspend(ctx, "cargo-transfer", "1.0.0", at.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Resolve(ctx, "cargo-transfer", at.Add(time.Minute)); !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("suspended policy remained resolvable: %v", err)
	}
	if err := registry.Retire(ctx, "cargo-transfer", "1.0.0", at.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := registry.Suspend(ctx, "cargo-transfer", "1.0.0", at.Add(4*time.Minute)); !errors.Is(err, ErrInvalidLifecycleChange) {
		t.Fatalf("retired policy accepted transition: %v", err)
	}
}
