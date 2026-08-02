package responsibility

import (
	"context"
	"errors"
	"time"
)

var ErrRepositoryRequired = errors.New("responsibility: repository is required")

type Service struct {
	repository Repository
}

func NewService(repository Repository) (*Service, error) {
	if repository == nil {
		return nil, ErrRepositoryRequired
	}
	return &Service{repository: repository}, nil
}

// Transfer commits the new sole assignment and its immutable handover event as
// one repository operation. A failed commit leaves durable state unchanged.
func (service *Service) Transfer(
	ctx context.Context,
	objectID PhysicalObjectID,
	to ParticipantID,
	transferredAt time.Time,
) (Snapshot, error) {
	if service == nil || service.repository == nil {
		return Snapshot{}, ErrRepositoryRequired
	}
	aggregate, err := service.repository.FindResponsibility(ctx, objectID)
	if err != nil {
		return Snapshot{}, err
	}
	return service.transferLoaded(ctx, aggregate, to, transferredAt)
}

// TransferExpected rejects a handover if responsibility changed after its
// safety authorization was evaluated.
func (service *Service) TransferExpected(
	ctx context.Context,
	expected Snapshot,
	to ParticipantID,
	transferredAt time.Time,
) (Snapshot, error) {
	if service == nil || service.repository == nil {
		return Snapshot{}, ErrRepositoryRequired
	}
	validated, err := Rehydrate(expected)
	if err != nil {
		return Snapshot{}, err
	}
	expected = validated.Snapshot()
	aggregate, err := service.repository.FindResponsibility(ctx, expected.ObjectID)
	if err != nil {
		return Snapshot{}, err
	}
	if aggregate.Snapshot() != expected {
		return Snapshot{}, ErrConcurrentModification
	}
	return service.transferLoaded(ctx, aggregate, to, transferredAt)
}

func (service *Service) transferLoaded(
	ctx context.Context,
	aggregate *Aggregate,
	to ParticipantID,
	transferredAt time.Time,
) (Snapshot, error) {
	expectedVersion := aggregate.Snapshot().Version
	if err := aggregate.Transfer(to, transferredAt); err != nil {
		return Snapshot{}, err
	}
	event, exists := aggregate.PendingTransfer()
	if !exists {
		return Snapshot{}, ErrInvalidTransferCommit
	}
	snapshot := aggregate.Snapshot()
	if err := service.repository.CommitTransfer(ctx, snapshot, expectedVersion, event); err != nil {
		return Snapshot{}, err
	}
	aggregate.ClearPendingEvents()
	return snapshot, nil
}
