package safety

import (
	"context"
	"errors"
	"testing"
	"time"

	"cargoos/responsibility"
)

func safetyFixture(t *testing.T) (*Machine, *responsibility.Service, Permit, time.Time) {
	t.Helper()
	assignedAt := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	aggregate, err := responsibility.New("parcel-42", "vehicle-7", assignedAt)
	if err != nil {
		t.Fatal(err)
	}
	repository := responsibility.NewMemoryRepository()
	if err = repository.SaveResponsibility(context.Background(), aggregate.Snapshot(), 0); err != nil {
		t.Fatal(err)
	}
	service, err := responsibility.NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := NewMachine(aggregate.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	now := assignedAt.Add(time.Minute)
	permit := Permit{
		ObjectID: "parcel-42", FromParticipantID: "vehicle-7", ToParticipantID: "warehouse-3",
		PolicyID: "handover-policy", PolicyVersion: "v3", EvidenceVersion: "bundle-v7",
		EvaluatedAt: now, ValidUntil: now.Add(time.Minute), Admissible: true,
	}
	return machine, service, permit, now
}

func TestVerifiedHandoverCommitsResponsibility(t *testing.T) {
	machine, service, permit, now := safetyFixture(t)
	if err := machine.Propose("warehouse-3"); err != nil {
		t.Fatal(err)
	}
	if err := machine.Verify(permit, now); err != nil {
		t.Fatal(err)
	}
	updated, err := machine.Commit(context.Background(), service, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	state := machine.Snapshot()
	if state.State != StateCommitted || updated.ParticipantID != "warehouse-3" || !machine.MotionAllowed() {
		t.Fatalf("unexpected committed state: %#v", state)
	}
}

func TestInvalidEvidenceEntersHaltAndRetainsResponsibility(t *testing.T) {
	machine, service, permit, now := safetyFixture(t)
	initial := machine.Snapshot().Responsibility
	if err := machine.Propose("warehouse-3"); err != nil {
		t.Fatal(err)
	}
	permit.Admissible = false
	if err := machine.Verify(permit, now); !errors.Is(err, ErrInvalidPermit) {
		t.Fatalf("expected invalid permit, got %v", err)
	}
	state := machine.Snapshot()
	if state.State != StateHalt || state.Responsibility != initial || machine.MotionAllowed() {
		t.Fatalf("halt did not retain responsibility: %#v", state)
	}
	if _, err := machine.Commit(context.Background(), service, now.Add(time.Second)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("halt allowed commit: %v", err)
	}
}

func TestRecoveryRequiresFreshVersionedEvidenceForRetainedParticipant(t *testing.T) {
	machine, _, permit, now := safetyFixture(t)
	machine.Halt(ReasonManualHalt)
	permit.ToParticipantID = "vehicle-7"
	permit.ValidUntil = now.Add(-time.Second)
	if err := machine.Recover(permit, now); !errors.Is(err, ErrInvalidPermit) {
		t.Fatalf("expired recovery unexpectedly succeeded: %v", err)
	}
	if machine.Snapshot().State != StateHalt || machine.Snapshot().Responsibility.ParticipantID != "vehicle-7" {
		t.Fatal("failed recovery changed halt responsibility")
	}
	permit.EvaluatedAt = now
	permit.ValidUntil = now.Add(time.Minute)
	permit.EvidenceVersion = "bundle-v8"
	if err := machine.Recover(permit, now); err != nil {
		t.Fatal(err)
	}
	if state := machine.Snapshot(); state.State != StateIdle || state.Responsibility.ParticipantID != "vehicle-7" {
		t.Fatalf("unexpected recovered state: %#v", state)
	}
}

func TestConcurrentResponsibilityChangeFailsClosed(t *testing.T) {
	machine, service, permit, now := safetyFixture(t)
	if err := machine.Propose("warehouse-3"); err != nil {
		t.Fatal(err)
	}
	if err := machine.Verify(permit, now); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Transfer(context.Background(), "parcel-42", "hub-9", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := machine.Commit(context.Background(), service, now.Add(2*time.Second)); !errors.Is(err, responsibility.ErrConcurrentModification) {
		t.Fatalf("expected stale authorization conflict, got %v", err)
	}
	state := machine.Snapshot()
	if state.State != StateHalt || state.Reason != ReasonConcurrentChange || state.Responsibility.ParticipantID != "vehicle-7" {
		t.Fatalf("stale authorization did not fail closed: %#v", state)
	}
}
