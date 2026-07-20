package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

type MemoryRepository struct {
	mu      sync.RWMutex
	objects map[uuid.UUID]Snapshot
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{objects: make(map[uuid.UUID]Snapshot)}
}

func (m *MemoryRepository) SaveEvidence(_ context.Context, snapshot Snapshot) error {
	object, err := Rehydrate(snapshot)
	if err != nil {
		return err
	}
	normalized := object.Snapshot()
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, found := m.objects[normalized.EvidenceID]; found {
		if SameSubmission(existing, normalized) {
			return nil
		}
		return ErrConflict
	}
	m.objects[normalized.EvidenceID] = normalized
	return nil
}

func (m *MemoryRepository) FindEvidence(_ context.Context, id uuid.UUID) (*Object, error) {
	if id == uuid.Nil {
		return nil, ErrEvidenceIDRequired
	}
	m.mu.RLock()
	snapshot, found := m.objects[id]
	m.mu.RUnlock()
	if !found {
		return nil, ErrNotFound
	}
	return Rehydrate(snapshot)
}

func (m *MemoryRepository) ListEvidenceBySession(_ context.Context, sessionID uuid.UUID) ([]*Object, error) {
	if sessionID == uuid.Nil {
		return nil, ErrSessionIDRequired
	}
	m.mu.RLock()
	snapshots := make([]Snapshot, 0)
	for _, snapshot := range m.objects {
		if snapshot.SessionID == sessionID {
			snapshots = append(snapshots, copySnapshot(snapshot))
		}
	}
	m.mu.RUnlock()
	sort.Slice(snapshots, func(left, right int) bool {
		if snapshots[left].ObservedAt.Equal(snapshots[right].ObservedAt) {
			return snapshots[left].EvidenceID.String() < snapshots[right].EvidenceID.String()
		}
		return snapshots[left].ObservedAt.Before(snapshots[right].ObservedAt)
	})
	objects := make([]*Object, 0, len(snapshots))
	for _, snapshot := range snapshots {
		object, err := Rehydrate(snapshot)
		if err != nil {
			return nil, err
		}
		objects = append(objects, object)
	}
	return objects, nil
}

func snapshotsEqual(left, right Snapshot) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

// SameSubmission compares immutable client-supplied evidence while ignoring
// ReceivedAt, which is assigned by the accepting service and may differ when a
// request is retried after its first successful commit.
func SameSubmission(left, right Snapshot) bool {
	left.ReceivedAt = time.Time{}
	right.ReceivedAt = time.Time{}
	return snapshotsEqual(left, right)
}

var _ Repository = (*MemoryRepository)(nil)
