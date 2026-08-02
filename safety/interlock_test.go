package safety

import (
	"testing"
	"time"
)

func TestMotionInterlockAllowsOnlyExactVerifiedBinding(t *testing.T) {
	machine, _, permit, now := safetyFixture(t)
	if err := machine.Propose("warehouse-3"); err != nil {
		t.Fatal(err)
	}
	if err := machine.Verify(permit, now); err != nil {
		t.Fatal(err)
	}
	decision := machine.AuthorizeMotion(MotionRequest{
		CommandID: "surface-transfer", Sequence: 1,
		ObjectID: "parcel-42", ResponsibleParticipant: "vehicle-7",
		TargetParticipant: "warehouse-3",
	}, now.Add(time.Second))
	if !decision.Allowed || decision.Reason != ReasonNone || decision.State != StateVerified ||
		decision.PolicyVersion != permit.PolicyVersion || decision.EvidenceVersion != permit.EvidenceVersion {
		t.Fatalf("unexpected motion decision: %#v", decision)
	}
}

func TestMotionInterlockFailsClosedOnSubstitutionAndExpiry(t *testing.T) {
	t.Run("substituted target", func(t *testing.T) {
		machine, _, permit, now := safetyFixture(t)
		if err := machine.Propose("warehouse-3"); err != nil {
			t.Fatal(err)
		}
		if err := machine.Verify(permit, now); err != nil {
			t.Fatal(err)
		}
		decision := machine.AuthorizeMotion(MotionRequest{
			CommandID: "surface-transfer", Sequence: 1,
			ObjectID: "parcel-42", ResponsibleParticipant: "vehicle-7",
			TargetParticipant: "other-target",
		}, now.Add(time.Second))
		if decision.Allowed || decision.Reason != ReasonAuthorizationBinding ||
			machine.Snapshot().State != StateHalt || machine.MotionAllowed() {
			t.Fatalf("substituted motion did not fail closed: %#v", decision)
		}
	})

	t.Run("expired permit", func(t *testing.T) {
		machine, _, permit, now := safetyFixture(t)
		if err := machine.Propose("warehouse-3"); err != nil {
			t.Fatal(err)
		}
		if err := machine.Verify(permit, now); err != nil {
			t.Fatal(err)
		}
		decision := machine.AuthorizeMotion(MotionRequest{
			CommandID: "surface-transfer", Sequence: 1,
			ObjectID: "parcel-42", ResponsibleParticipant: "vehicle-7",
			TargetParticipant: "warehouse-3",
		}, permit.ValidUntil.Add(time.Nanosecond))
		if decision.Allowed || decision.Reason != ReasonEvidenceExpired ||
			machine.Snapshot().State != StateHalt {
			t.Fatalf("expired permit did not halt motion: %#v", decision)
		}
	})
}

func TestMotionInterlockBlocksEveryNonVerifiedState(t *testing.T) {
	machine, _, _, now := safetyFixture(t)
	request := MotionRequest{
		CommandID: "surface-transfer", Sequence: 1,
		ObjectID: "parcel-42", ResponsibleParticipant: "vehicle-7",
		TargetParticipant: "warehouse-3",
	}
	if decision := machine.AuthorizeMotion(request, now); decision.Allowed || decision.Reason != ReasonMotionStateBlocked {
		t.Fatalf("IDLE unexpectedly enabled motion: %#v", decision)
	}
	machine.Halt(ReasonManualHalt)
	if decision := machine.AuthorizeMotion(request, now); decision.Allowed || decision.State != StateHalt {
		t.Fatalf("HALT unexpectedly enabled motion: %#v", decision)
	}
}
