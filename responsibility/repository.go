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
)

// Repository durably enforces one versioned responsibility snapshot per
// Physical Object. expectedVersion is zero only for the initial assignment.
type Repository interface {
	SaveResponsibility(context.Context, Snapshot, uint64) error
	FindResponsibility(context.Context, PhysicalObjectID) (*Aggregate, error)
}

type MemoryRepository struct {
	mu        sync.RWMutex
	snapshots map[PhysicalObjectID]Snapshot
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{snapshots: make(map[PhysicalObjectID]Snapshot)}
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

var _ Repository = (*MemoryRepository)(nil)
