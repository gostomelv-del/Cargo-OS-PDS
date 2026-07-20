package pds

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"

	"cargoos/evaluation"
)

var ErrConcurrentModification = errors.New("pds: concurrent modification")

type MemoryStore struct {
	mu        sync.RWMutex
	snapshots map[uuid.UUID]evaluation.EvaluationSnapshot
	outbox    []evaluation.OutboxRecord
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{snapshots: make(map[uuid.UUID]evaluation.EvaluationSnapshot)}
}

func (m *MemoryStore) SaveEvaluation(
	_ context.Context,
	snapshot evaluation.EvaluationSnapshot,
	expectedVersion uint64,
	records []evaluation.OutboxRecord,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, exists := m.snapshots[snapshot.EvaluationID]
	switch {
	case expectedVersion == 0 && exists:
		return ErrConcurrentModification
	case expectedVersion > 0 && (!exists || current.Version != expectedVersion):
		return ErrConcurrentModification
	}
	aggregate, err := evaluation.RehydrateEvaluation(snapshot)
	if err != nil {
		return err
	}
	copySnapshot, err := aggregate.Snapshot()
	if err != nil {
		return err
	}
	m.snapshots[snapshot.EvaluationID] = copySnapshot
	m.outbox = append(m.outbox, copyOutboxRecords(records)...)
	return nil
}

func (m *MemoryStore) FindEvaluation(
	_ context.Context,
	id uuid.UUID,
) (*evaluation.EvaluationAggregate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	snapshot, exists := m.snapshots[id]
	if !exists {
		return nil, ErrEvaluationNotFound
	}
	return evaluation.RehydrateEvaluation(snapshot)
}

func (m *MemoryStore) OutboxRecords() []evaluation.OutboxRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return copyOutboxRecords(m.outbox)
}

func copyOutboxRecords(records []evaluation.OutboxRecord) []evaluation.OutboxRecord {
	if len(records) == 0 {
		return nil
	}
	copied := make([]evaluation.OutboxRecord, len(records))
	copy(copied, records)
	for index := range copied {
		copied[index].Payload = append([]byte(nil), copied[index].Payload...)
	}
	return copied
}

var _ AggregateStore = (*MemoryStore)(nil)
