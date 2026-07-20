package evidence

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrRepositoryRequired = errors.New("evidence: repository is required")
	ErrNotFound           = errors.New("evidence: object not found")
	ErrConflict           = errors.New("evidence: identifier already contains different evidence")
)

type Repository interface {
	SaveEvidence(context.Context, Snapshot) error
	FindEvidence(context.Context, uuid.UUID) (*Object, error)
	ListEvidenceBySession(context.Context, uuid.UUID) ([]*Object, error)
}

type Clock func() time.Time

type ServiceConfig struct {
	SchemaVersion  string
	RuntimeVersion string
	Clock          Clock
}

type Service struct {
	repository     Repository
	schemaVersion  string
	runtimeVersion string
	now            Clock
}

func NewService(repository Repository, config ServiceConfig) (*Service, error) {
	if repository == nil {
		return nil, ErrRepositoryRequired
	}
	schemaVersion := strings.TrimSpace(config.SchemaVersion)
	if schemaVersion == "" {
		return nil, ErrSchemaVersionRequired
	}
	runtimeVersion := strings.TrimSpace(config.RuntimeVersion)
	if runtimeVersion == "" {
		return nil, ErrRuntimeVersionRequired
	}
	now := config.Clock
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{
		repository: repository, schemaVersion: schemaVersion,
		runtimeVersion: runtimeVersion, now: now,
	}, nil
}

// Ingest creates, validates, and atomically stores canonical evidence. Schema,
// runtime, and receipt time are controlled by the service rather than callers.
func (s *Service) Ingest(ctx context.Context, input Input) (Snapshot, error) {
	if input.EvidenceID == uuid.Nil {
		input.EvidenceID = uuid.New()
	}
	input.ReceivedAt = s.now().UTC()
	input.SchemaVersion = s.schemaVersion
	input.RuntimeVersion = s.runtimeVersion
	object, err := NewObject(input)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot := object.Snapshot()
	if err = s.repository.SaveEvidence(ctx, snapshot); err != nil {
		return Snapshot{}, err
	}
	stored, err := s.repository.FindEvidence(ctx, snapshot.EvidenceID)
	if err != nil {
		return Snapshot{}, err
	}
	return stored.Snapshot(), nil
}

func (s *Service) Find(ctx context.Context, id uuid.UUID) (Snapshot, error) {
	object, err := s.repository.FindEvidence(ctx, id)
	if err != nil {
		return Snapshot{}, err
	}
	if object == nil {
		return Snapshot{}, ErrNotFound
	}
	return object.Snapshot(), nil
}

func (s *Service) ListBySession(ctx context.Context, sessionID uuid.UUID) ([]Snapshot, error) {
	if sessionID == uuid.Nil {
		return nil, ErrSessionIDRequired
	}
	objects, err := s.repository.ListEvidenceBySession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	snapshots := make([]Snapshot, 0, len(objects))
	for _, object := range objects {
		if object == nil {
			return nil, ErrNotFound
		}
		snapshots = append(snapshots, object.Snapshot())
	}
	return snapshots, nil
}
