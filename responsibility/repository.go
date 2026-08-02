package responsibility

import (
	"context"
	"errors"
	"sync"
)

var (
	ErrNotFound                 = errors.New("responsibility: assignment not found")
	ErrConcurrentModification   = errors.New("responsibility: concurrent modification")
	ErrInvalidVersionTransition = errors.New("responsibility: snapshot version must advance by one")
	ErrInvalidTransferCommit    = errors.New("responsibility: transfer commit does not match snapshot")
	ErrTransferNotFound         = errors.New("responsibility: transfer event not found")
)

// Repository durably enforces one versioned responsibility snapshot per
// Physical Object. expectedVersion is zero only for the initial assignment.
type Repository interface {
	SaveResponsibility(context.Context, Snapshot, uint64) error
	FindResponsibility(context.Context, PhysicalObjectID) (*Aggregate, error)
	CommitTransfer(context.Context, Snapshot, uint64, TransferredEvent) error
	FindTransfer(context.Context, PhysicalObjectID, uint64) (TransferredEvent, error)
}

type transferKey struct {
	objectID PhysicalObjectID
	version  uint64
}

type MemoryRepository struct {
	mu        sync.RWMutex
	snapshots map[PhysicalObjectID]Snapshot
	transfers map[transferKey]TransferredEvent
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		snapshots: make(map[PhysicalObjectID]Snapshot),
		transfers: make(map[transferKey]TransferredEvent),
	}
}

func (repository *MemoryRepository) CommitTransfer(
	_ context.Context,
	snapshot Snapshot,
	expectedVersion uint64,
	event TransferredEvent,
) error {
	normalized, err := ValidateTransferCommit(snapshot, expectedVersion, event)
	if err != nil {
		return err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	current, exists := repository.snapshots[normalized.ObjectID]
	if !exists || current.Version != expectedVersion ||
		current.ParticipantID != event.FromParticipantID ||
		!normalized.AssignedAt.After(current.AssignedAt) {
		return ErrConcurrentModification
	}
	key := transferKey{objectID: normalized.ObjectID, version: normalized.Version}
	if _, exists = repository.transfers[key]; exists {
		return ErrConcurrentModification
	}
	event.TransferredAt = normalized.AssignedAt
	repository.snapshots[normalized.ObjectID] = normalized
	repository.transfers[key] = event
	return nil
}

func (repository *MemoryRepository) FindTransfer(
	_ context.Context,
	objectID PhysicalObjectID,
	version uint64,
) (TransferredEvent, error) {
	if err := validateObjectID(objectID); err != nil {
		return TransferredEvent{}, err
	}
	repository.mu.RLock()
	event, exists := repository.transfers[transferKey{objectID: objectID, version: version}]
	repository.mu.RUnlock()
	if !exists {
		return TransferredEvent{}, ErrTransferNotFound
	}
	return event, nil
}

func (repository *MemoryRepository) SaveResponsibility(
	_ context.Context,
	snapshot Snapshot,
	expectedVersion uint64,
) error {
	normalized, err := normalizedSnapshot(snapshot, expectedVersion)
	if err != nil {
		return err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	current, exists := repository.snapshots[normalized.ObjectID]
	if expectedVersion == 0 {
		if exists {
			return ErrConcurrentModification
		}
	} else if !exists || current.Version != expectedVersion ||
		current.ParticipantID == normalized.ParticipantID ||
		!normalized.AssignedAt.After(current.AssignedAt) {
		return ErrConcurrentModification
	}
	repository.snapshots[normalized.ObjectID] = normalized
	return nil
}

func (repository *MemoryRepository) FindResponsibility(
	_ context.Context,
	objectID PhysicalObjectID,
) (*Aggregate, error) {
	if err := validateObjectID(objectID); err != nil {
		return nil, err
	}
	repository.mu.RLock()
	snapshot, exists := repository.snapshots[objectID]
	repository.mu.RUnlock()
	if !exists {
		return nil, ErrNotFound
	}
	return Rehydrate(snapshot)
}

func normalizedSnapshot(snapshot Snapshot, expectedVersion uint64) (Snapshot, error) {
	aggregate, err := Rehydrate(snapshot)
	if err != nil {
		return Snapshot{}, err
	}
	if expectedVersion == ^uint64(0) || aggregate.version != expectedVersion+1 {
		return Snapshot{}, ErrInvalidVersionTransition
	}
	return aggregate.Snapshot(), nil
}

func ValidateTransferCommit(
	snapshot Snapshot,
	expectedVersion uint64,
	event TransferredEvent,
) (Snapshot, error) {
	normalized, err := normalizedSnapshot(snapshot, expectedVersion)
	if err != nil {
		return Snapshot{}, err
	}
	if expectedVersion == 0 || event.ObjectID != normalized.ObjectID ||
		event.FromParticipantID == event.ToParticipantID ||
		event.ToParticipantID != normalized.ParticipantID ||
		event.Version != normalized.Version ||
		!event.TransferredAt.Equal(normalized.AssignedAt) {
		return Snapshot{}, ErrInvalidTransferCommit
	}
	if err = validateTransferredEvent(event); err != nil {
		return Snapshot{}, ErrInvalidTransferCommit
	}
	return normalized, nil
}

var _ Repository = (*MemoryRepository)(nil)
