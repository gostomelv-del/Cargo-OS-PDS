package responsibility

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
)

var (
	ErrObjectIDRequired      = errors.New("responsibility: physical object ID is required")
	ErrParticipantIDRequired = errors.New("responsibility: participant ID is required")
	ErrAssignmentTime        = errors.New("responsibility: assignment time is required")
	ErrInvalidSnapshot       = errors.New("responsibility: invalid snapshot")
	ErrSameParticipant       = errors.New("responsibility: transfer target is already responsible")
	ErrTransferTime          = errors.New("responsibility: transfer time must follow the current assignment")
	ErrTransferEventInvalid  = errors.New("responsibility: transfer event is invalid")
	ErrTransferAuditInvalid  = errors.New("responsibility: transfer audit binding is invalid")
)

type PhysicalObjectID string

func NewPhysicalObjectID(value string) (PhysicalObjectID, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ErrObjectIDRequired
	}
	return PhysicalObjectID(value), nil
}

func (id PhysicalObjectID) String() string { return string(id) }

type ParticipantID string

func NewParticipantID(value string) (ParticipantID, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ErrParticipantIDRequired
	}
	return ParticipantID(value), nil
}

func (id ParticipantID) String() string { return string(id) }

type Snapshot struct {
	ObjectID      PhysicalObjectID `json:"object_id"`
	ParticipantID ParticipantID    `json:"participant_id"`
	Version       uint64           `json:"version"`
	AssignedAt    time.Time        `json:"assigned_at"`
}

type TransferredEvent struct {
	ObjectID          PhysicalObjectID `json:"object_id"`
	FromParticipantID ParticipantID    `json:"from_participant_id"`
	ToParticipantID   ParticipantID    `json:"to_participant_id"`
	TransferredAt     time.Time        `json:"transferred_at"`
	Version           uint64           `json:"version"`
}

const transferRootDomain = "cargoos:responsibility-transfer:v1"

func TransferredEventRoot(event TransferredEvent) ([32]byte, error) {
	if err := validateTransferredEvent(event); err != nil {
		return [32]byte{}, err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(transferRootDomain))
	writeRootString(digest, event.ObjectID.String())
	writeRootString(digest, event.FromParticipantID.String())
	writeRootString(digest, event.ToParticipantID.String())
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], event.Version)
	_, _ = digest.Write(scalar[:])
	binary.BigEndian.PutUint64(scalar[:], uint64(event.TransferredAt.UnixMicro()))
	_, _ = digest.Write(scalar[:])
	var root [32]byte
	digest.Sum(root[:0])
	return root, nil
}

func writeRootString(digest hash.Hash, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = digest.Write(size[:])
	_, _ = digest.Write([]byte(value))
}

type Aggregate struct {
	objectID      PhysicalObjectID
	participantID ParticipantID
	version       uint64
	assignedAt    time.Time
	pendingEvent  TransferredEvent
	hasPending    bool
}

// New establishes the mandatory initial responsibility. An Aggregate cannot
// exist without exactly one Physical Object and exactly one Participant.
func New(objectID PhysicalObjectID, participantID ParticipantID, assignedAt time.Time) (*Aggregate, error) {
	snapshot := Snapshot{ObjectID: objectID, ParticipantID: participantID, Version: 1, AssignedAt: assignedAt.UTC()}
	if err := validateSnapshot(snapshot); err != nil {
		return nil, err
	}
	return &Aggregate{
		objectID: snapshot.ObjectID, participantID: snapshot.ParticipantID,
		version: snapshot.Version, assignedAt: snapshot.AssignedAt,
	}, nil
}

func Rehydrate(snapshot Snapshot) (*Aggregate, error) {
	snapshot.AssignedAt = snapshot.AssignedAt.UTC()
	if err := validateSnapshot(snapshot); err != nil {
		return nil, err
	}
	return &Aggregate{
		objectID: snapshot.ObjectID, participantID: snapshot.ParticipantID,
		version: snapshot.Version, assignedAt: snapshot.AssignedAt,
	}, nil
}

// Transfer atomically replaces the sole responsible Participant. The previous
// assignment remains unchanged when validation fails.
func (aggregate *Aggregate) Transfer(to ParticipantID, transferredAt time.Time) error {
	if aggregate == nil {
		return ErrInvalidSnapshot
	}
	if err := validateParticipantID(to); err != nil {
		return err
	}
	if to == aggregate.participantID {
		return ErrSameParticipant
	}
	transferredAt = transferredAt.UTC()
	if transferredAt.IsZero() || !transferredAt.After(aggregate.assignedAt) {
		return ErrTransferTime
	}
	nextVersion := aggregate.version + 1
	event := TransferredEvent{
		ObjectID: aggregate.objectID, FromParticipantID: aggregate.participantID,
		ToParticipantID: to, TransferredAt: transferredAt, Version: nextVersion,
	}
	aggregate.participantID = to
	aggregate.assignedAt = transferredAt
	aggregate.version = nextVersion
	aggregate.pendingEvent = event
	aggregate.hasPending = true
	return nil
}

func (aggregate *Aggregate) Snapshot() Snapshot {
	if aggregate == nil {
		return Snapshot{}
	}
	return Snapshot{
		ObjectID: aggregate.objectID, ParticipantID: aggregate.participantID,
		Version: aggregate.version, AssignedAt: aggregate.assignedAt,
	}
}

func (aggregate *Aggregate) PendingEvents() []TransferredEvent {
	if aggregate == nil || !aggregate.hasPending {
		return nil
	}
	return []TransferredEvent{aggregate.pendingEvent}
}

// PendingTransfer returns the sole event produced by the latest Transfer
// without allocating a defensive slice.
func (aggregate *Aggregate) PendingTransfer() (TransferredEvent, bool) {
	if aggregate == nil || !aggregate.hasPending {
		return TransferredEvent{}, false
	}
	return aggregate.pendingEvent, true
}

func (aggregate *Aggregate) ClearPendingEvents() {
	if aggregate != nil {
		aggregate.pendingEvent = TransferredEvent{}
		aggregate.hasPending = false
	}
}

func validateSnapshot(snapshot Snapshot) error {
	if snapshot.Version == 0 {
		return ErrInvalidSnapshot
	}
	if err := validateObjectID(snapshot.ObjectID); err != nil {
		return err
	}
	if err := validateParticipantID(snapshot.ParticipantID); err != nil {
		return err
	}
	if snapshot.AssignedAt.IsZero() {
		return ErrAssignmentTime
	}
	return nil
}

func validateObjectID(id PhysicalObjectID) error {
	if id == "" || string(id) != strings.TrimSpace(string(id)) {
		return fmt.Errorf("%w: %q", ErrObjectIDRequired, id)
	}
	return nil
}

func validateParticipantID(id ParticipantID) error {
	if id == "" || string(id) != strings.TrimSpace(string(id)) {
		return fmt.Errorf("%w: %q", ErrParticipantIDRequired, id)
	}
	return nil
}

func validateTransferredEvent(event TransferredEvent) error {
	if event.Version < 2 || event.FromParticipantID == event.ToParticipantID ||
		event.TransferredAt.IsZero() {
		return ErrTransferEventInvalid
	}
	if err := validateObjectID(event.ObjectID); err != nil {
		return ErrTransferEventInvalid
	}
	if err := validateParticipantID(event.FromParticipantID); err != nil {
		return ErrTransferEventInvalid
	}
	if err := validateParticipantID(event.ToParticipantID); err != nil {
		return ErrTransferEventInvalid
	}
	return nil
}
