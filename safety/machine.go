package safety

import (
	"context"
	"errors"
	"strings"
	"time"

	"cargoos/responsibility"
)

type State string

const (
	StateIdle      State = "IDLE"
	StateProposed  State = "PROPOSED"
	StateVerified  State = "VERIFIED"
	StateCommitted State = "COMMITTED"
	StateRejected  State = "REJECTED"
	StateHalt      State = "HALT"
)

type Reason string

const (
	ReasonNone                 Reason = "NONE"
	ReasonInvalidTransition    Reason = "INVALID_TRANSITION"
	ReasonInvalidEvidence      Reason = "INVALID_EVIDENCE"
	ReasonEvidenceExpired      Reason = "EVIDENCE_EXPIRED"
	ReasonAuthorizationBinding Reason = "AUTHORIZATION_BINDING_MISMATCH"
	ReasonConcurrentChange     Reason = "CONCURRENT_RESPONSIBILITY_CHANGE"
	ReasonCommitFailed         Reason = "COMMIT_FAILED"
	ReasonManualHalt           Reason = "MANUAL_HALT"
)

var (
	ErrInvalidTransition = errors.New("safety: invalid state transition")
	ErrInvalidPermit     = errors.New("safety: invalid permit")
	ErrServiceRequired   = errors.New("safety: responsibility service is required")
)

type Permit struct {
	ObjectID          responsibility.PhysicalObjectID
	FromParticipantID responsibility.ParticipantID
	ToParticipantID   responsibility.ParticipantID
	PolicyID          string
	PolicyVersion     string
	EvidenceVersion   string
	EvaluatedAt       time.Time
	ValidUntil        time.Time
	Admissible        bool
}

type Snapshot struct {
	State                 State
	Reason                Reason
	Responsibility        responsibility.Snapshot
	ProposedParticipantID responsibility.ParticipantID
}

type Machine struct {
	state          State
	reason         Reason
	responsibility responsibility.Snapshot
	proposed          responsibility.ParticipantID
	verifiedPermit    Permit
	hasVerifiedPermit bool
}

func NewMachine(current responsibility.Snapshot) (*Machine, error) {
	aggregate, err := responsibility.Rehydrate(current)
	if err != nil {
		return nil, err
	}
	return &Machine{state: StateIdle, reason: ReasonNone, responsibility: aggregate.Snapshot()}, nil
}

func (machine *Machine) Snapshot() Snapshot {
	if machine == nil {
		return Snapshot{}
	}
	return Snapshot{
		State: machine.state, Reason: machine.reason,
		Responsibility:        machine.responsibility,
		ProposedParticipantID: machine.proposed,
	}
}

func (machine *Machine) MotionAllowed() bool {
	if machine == nil {
		return false
	}
	return machine.state == StateIdle || machine.state == StateVerified || machine.state == StateCommitted
}

func (machine *Machine) Propose(to responsibility.ParticipantID) error {
	if machine == nil || (machine.state != StateIdle && machine.state != StateCommitted) {
		return ErrInvalidTransition
	}
	validated, err := responsibility.NewParticipantID(to.String())
	if err != nil || validated != to || to == machine.responsibility.ParticipantID {
		machine.state = StateRejected
		machine.reason = ReasonInvalidTransition
		return ErrInvalidTransition
	}
	machine.clearVerifiedPermit()
	machine.proposed = to
	machine.state = StateProposed
	machine.reason = ReasonNone
	return nil
}

func (machine *Machine) Verify(permit Permit, now time.Time) error {
	if machine == nil || machine.state != StateProposed {
		return ErrInvalidTransition
	}
	reason := machine.validatePermit(permit, now, machine.proposed)
	if reason != ReasonNone {
		machine.enterHalt(reason)
		return ErrInvalidPermit
	}
	permit.EvaluatedAt = permit.EvaluatedAt.UTC()
	permit.ValidUntil = permit.ValidUntil.UTC()
	machine.verifiedPermit = permit
	machine.hasVerifiedPermit = true
	machine.state = StateVerified
	machine.reason = ReasonNone
	return nil
}

func (machine *Machine) Commit(
	ctx context.Context,
	service *responsibility.Service,
	committedAt time.Time,
) (responsibility.Snapshot, error) {
	if machine == nil || machine.state != StateVerified {
		return responsibility.Snapshot{}, ErrInvalidTransition
	}
	if service == nil {
		machine.enterHalt(ReasonCommitFailed)
		return responsibility.Snapshot{}, ErrServiceRequired
	}
	updated, err := service.TransferExpected(ctx, machine.responsibility, machine.proposed, committedAt)
	if err != nil {
		if errors.Is(err, responsibility.ErrConcurrentModification) {
			machine.enterHalt(ReasonConcurrentChange)
		} else {
			machine.enterHalt(ReasonCommitFailed)
		}
		return responsibility.Snapshot{}, err
	}
	machine.responsibility = updated
	machine.proposed = ""
	machine.clearVerifiedPermit()
	machine.state = StateCommitted
	machine.reason = ReasonNone
	return updated, nil
}

func (machine *Machine) Halt(reason Reason) {
	if reason == ReasonNone {
		reason = ReasonManualHalt
	}
	machine.enterHalt(reason)
}

func (machine *Machine) Recover(permit Permit, now time.Time) error {
	if machine == nil || machine.state != StateHalt {
		return ErrInvalidTransition
	}
	reason := machine.validatePermit(permit, now, machine.responsibility.ParticipantID)
	if reason != ReasonNone {
		machine.reason = reason
		return ErrInvalidPermit
	}
	machine.proposed = ""
	machine.clearVerifiedPermit()
	machine.state = StateIdle
	machine.reason = ReasonNone
	return nil
}

func (machine *Machine) validatePermit(permit Permit, now time.Time, to responsibility.ParticipantID) Reason {
	if now.IsZero() || !permit.Admissible || strings.TrimSpace(permit.PolicyID) == "" ||
		strings.TrimSpace(permit.PolicyVersion) == "" || strings.TrimSpace(permit.EvidenceVersion) == "" ||
		permit.EvaluatedAt.IsZero() || permit.ValidUntil.IsZero() {
		return ReasonInvalidEvidence
	}
	if permit.ObjectID != machine.responsibility.ObjectID ||
		permit.FromParticipantID != machine.responsibility.ParticipantID || permit.ToParticipantID != to {
		return ReasonAuthorizationBinding
	}
	now = now.UTC()
	if permit.EvaluatedAt.After(now) || now.After(permit.ValidUntil) ||
		permit.ValidUntil.Before(permit.EvaluatedAt) {
		return ReasonEvidenceExpired
	}
	return ReasonNone
}

func (machine *Machine) enterHalt(reason Reason) {
	if machine == nil {
		return
	}
	machine.proposed = ""
	machine.clearVerifiedPermit()
	machine.state = StateHalt
	machine.reason = reason
}

func (machine *Machine) clearVerifiedPermit() {
	machine.verifiedPermit = Permit{}
	machine.hasVerifiedPermit = false
}
