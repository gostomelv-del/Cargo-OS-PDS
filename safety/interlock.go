package safety

import (
	"strings"
	"time"

	"cargoos/responsibility"
)

const ReasonMotionStateBlocked Reason = "MOTION_STATE_BLOCKED"

// MotionRequest is the hardware-independent identity envelope for one motion
// command. Deployment adapters may translate CommandID, but may not change the
// Object, Participant, target, or sequence binding.
type MotionRequest struct {
	CommandID              string
	Sequence               uint64
	ObjectID               responsibility.PhysicalObjectID
	ResponsibleParticipant responsibility.ParticipantID
	TargetParticipant      responsibility.ParticipantID
}

// MotionDecision is the sole output a deployment adapter may use to enable a
// motion command. A zero value is always fail-closed.
type MotionDecision struct {
	Allowed                bool
	Reason                 Reason
	State                  State
	CommandID              string
	Sequence               uint64
	ObjectID               responsibility.PhysicalObjectID
	ResponsibleParticipant responsibility.ParticipantID
	TargetParticipant      responsibility.ParticipantID
	PolicyID               string
	PolicyVersion          string
	EvidenceVersion        string
	ValidUntil             time.Time
}

// AuthorizeMotion emits a deterministic, fixed-value decision from the exact
// Permit previously accepted by Verify. Invalid, expired, or substituted
// requests enter HALT and erase the stored authorization.
func (machine *Machine) AuthorizeMotion(request MotionRequest, now time.Time) MotionDecision {
	decision := MotionDecision{Reason: ReasonMotionStateBlocked}
	if machine == nil {
		return decision
	}
	decision.State = machine.state
	decision.ObjectID = machine.responsibility.ObjectID
	decision.ResponsibleParticipant = machine.responsibility.ParticipantID
	decision.TargetParticipant = machine.proposed
	if machine.state != StateVerified || !machine.hasVerifiedPermit {
		return decision
	}
	if strings.TrimSpace(request.CommandID) == "" || request.CommandID != strings.TrimSpace(request.CommandID) ||
		request.Sequence == 0 || request.ObjectID != machine.responsibility.ObjectID ||
		request.ResponsibleParticipant != machine.responsibility.ParticipantID ||
		request.TargetParticipant != machine.proposed {
		machine.enterHalt(ReasonAuthorizationBinding)
		decision.State = StateHalt
		decision.Reason = ReasonAuthorizationBinding
		return decision
	}
	permit := machine.verifiedPermit
	if reason := machine.validatePermit(permit, now, machine.proposed); reason != ReasonNone {
		machine.enterHalt(reason)
		decision.State = StateHalt
		decision.Reason = reason
		return decision
	}
	return MotionDecision{
		Allowed: true, Reason: ReasonNone, State: StateVerified,
		CommandID: request.CommandID, Sequence: request.Sequence,
		ObjectID: request.ObjectID, ResponsibleParticipant: request.ResponsibleParticipant,
		TargetParticipant: request.TargetParticipant, PolicyID: permit.PolicyID,
		PolicyVersion: permit.PolicyVersion, EvidenceVersion: permit.EvidenceVersion,
		ValidUntil: permit.ValidUntil,
	}
}
