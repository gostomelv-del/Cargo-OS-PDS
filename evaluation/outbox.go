package evaluation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrOutboxEventRequired          = errors.New("evaluation: outbox event is required")
	ErrOutboxEventTypeRequired      = errors.New("evaluation: outbox event type is required")
	ErrOutboxTimestampRequired      = errors.New("evaluation: outbox timestamp is required")
	ErrOutboxSerializationFailed    = errors.New("evaluation: outbox event serialization failed")
	ErrOutboxRecordNotFound         = errors.New("evaluation: outbox record not found")
	ErrOutboxAlreadyPublished       = errors.New("evaluation: outbox record already published")
	ErrOutboxAlreadyDeadLettered    = errors.New("evaluation: outbox record already dead-lettered")
	ErrOutboxPublishTimeRequired    = errors.New("evaluation: outbox publication time is required")
	ErrOutboxFailureTimeRequired    = errors.New("evaluation: outbox failure time is required")
	ErrOutboxFailureReasonRequired  = errors.New("evaluation: outbox failure reason is required")
	ErrOutboxInvalidRetrySchedule   = errors.New("evaluation: invalid outbox retry schedule")
	ErrOutboxMaximumAttemptsReached = errors.New("evaluation: outbox maximum attempts reached")
	ErrOutboxRepositoryUnavailable  = errors.New("evaluation: outbox repository unavailable")
	ErrOutboxClaimLimitInvalid      = errors.New("evaluation: outbox claim limit must be greater than zero")
	ErrOutboxWorkerIDRequired       = errors.New("evaluation: outbox worker ID is required")
	ErrOutboxLockDurationInvalid    = errors.New("evaluation: outbox lock duration must be greater than zero")
	ErrOutboxLockOwnershipMismatch  = errors.New("evaluation: outbox lock ownership mismatch")
	ErrOutboxConcurrentModification = errors.New("evaluation: outbox record concurrently modified")
)

type OutboxStatus string

const (
	OutboxStatusPending        OutboxStatus = "PENDING"
	OutboxStatusPublishing     OutboxStatus = "PUBLISHING"
	OutboxStatusPublished      OutboxStatus = "PUBLISHED"
	OutboxStatusRetryScheduled OutboxStatus = "RETRY_SCHEDULED"
	OutboxStatusDeadLettered   OutboxStatus = "DEAD_LETTERED"
)

func (s OutboxStatus) IsValid() bool {
	switch s {
	case OutboxStatusPending, OutboxStatusPublishing, OutboxStatusPublished, OutboxStatusRetryScheduled, OutboxStatusDeadLettered:
		return true
	}
	return false
}
func (s OutboxStatus) IsTerminal() bool {
	return s == OutboxStatusPublished || s == OutboxStatusDeadLettered
}

const DefaultOutboxMaxAttempts uint32 = 10

type OutboxRecord struct {
	ID                  uuid.UUID
	AggregateType       string
	AggregateID         uuid.UUID
	AggregateVersion    uint64
	EventType           string
	Payload             json.RawMessage
	Status              OutboxStatus
	OccurredAt          time.Time
	CreatedAt           time.Time
	PublishingStartedAt *time.Time
	PublishedAt         *time.Time
	NextAttemptAt       *time.Time
	LastAttemptAt       *time.Time
	DeadLetteredAt      *time.Time
	Attempts            uint32
	MaxAttempts         uint32
	LastError           string
	LockOwner           string
	LockUntil           *time.Time
}

func normalizeOutboxRecord(r OutboxRecord) OutboxRecord {
	if r.Status == "" {
		r.Status = OutboxStatusPending
	}
	if r.MaxAttempts == 0 {
		r.MaxAttempts = DefaultOutboxMaxAttempts
	}
	r.LockOwner = strings.TrimSpace(r.LockOwner)
	r.LastError = strings.TrimSpace(r.LastError)
	return r
}

func NewOutboxRecord(event DomainEvent, createdAt time.Time) (OutboxRecord, error) {
	if event == nil {
		return OutboxRecord{}, ErrOutboxEventRequired
	}
	if createdAt.IsZero() {
		return OutboxRecord{}, ErrOutboxTimestampRequired
	}
	value := reflect.ValueOf(event)
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return OutboxRecord{}, ErrOutboxEventRequired
		}
		value = value.Elem()
	}
	typ := value.Type()
	if typ.Name() == "" {
		return OutboxRecord{}, ErrOutboxEventTypeRequired
	}
	idField := value.FieldByName("EvaluationID")
	versionField := value.FieldByName("Version")
	if !idField.IsValid() || !versionField.IsValid() {
		return OutboxRecord{}, fmt.Errorf("%w: missing aggregate metadata", ErrOutboxEventRequired)
	}
	aggregateID, ok := idField.Interface().(uuid.UUID)
	if !ok || aggregateID == uuid.Nil {
		return OutboxRecord{}, ErrOutboxEventRequired
	}
	version := versionField.Uint()
	occurredAt := time.Time{}
	for _, name := range []string{"OccurredAt", "CreatedAt", "StartedAt", "CompletedAt", "RequiredAt", "RegisteredAt", "EvaluatedAt", "CancelledAt", "ExpiredAt", "RecordedAt", "ReplacedAt", "RemovedAt", "ResetAt", "CheckpointedAt", "RolledBackAt"} {
		f := value.FieldByName(name)
		if f.IsValid() {
			if t, ok := f.Interface().(time.Time); ok {
				occurredAt = t
				break
			}
		}
	}
	if occurredAt.IsZero() {
		return OutboxRecord{}, ErrOutboxTimestampRequired
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return OutboxRecord{}, fmt.Errorf("%w: %v", ErrOutboxSerializationFailed, err)
	}
	return normalizeOutboxRecord(OutboxRecord{ID: uuid.New(), AggregateType: "evaluation", AggregateID: aggregateID, AggregateVersion: version, EventType: typ.Name(), Payload: append(json.RawMessage(nil), payload...), Status: OutboxStatusPending, OccurredAt: occurredAt.UTC(), CreatedAt: createdAt.UTC()}), nil
}

func (e *EvaluationAggregate) BuildOutboxRecords(createdAt time.Time) ([]OutboxRecord, error) {
	if e == nil {
		return nil, ErrOutboxEventRequired
	}
	records := make([]OutboxRecord, 0, len(e.domainEvents))
	for _, event := range e.domainEvents {
		r, err := NewOutboxRecord(event, createdAt)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, nil
}

func (r *OutboxRecord) StartPublishing(workerID string, startedAt time.Time, lockDuration time.Duration) error {
	if r == nil {
		return ErrOutboxRecordNotFound
	}
	*r = normalizeOutboxRecord(*r)
	if r.Status == OutboxStatusPublished {
		return ErrOutboxAlreadyPublished
	}
	if r.Status == OutboxStatusDeadLettered {
		return ErrOutboxAlreadyDeadLettered
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return ErrOutboxWorkerIDRequired
	}
	if startedAt.IsZero() {
		return ErrOutboxPublishTimeRequired
	}
	if lockDuration <= 0 {
		return ErrOutboxLockDurationInvalid
	}
	startedAt = startedAt.UTC()
	until := startedAt.Add(lockDuration)
	r.Status = OutboxStatusPublishing
	r.PublishingStartedAt = &startedAt
	r.LastAttemptAt = &startedAt
	r.LockOwner = workerID
	r.LockUntil = &until
	r.Attempts++
	return nil
}
func (r *OutboxRecord) MarkPublished(workerID string, at time.Time) error {
	if r == nil {
		return ErrOutboxRecordNotFound
	}
	if r.Status == OutboxStatusPublished {
		return ErrOutboxAlreadyPublished
	}
	if strings.TrimSpace(workerID) == "" || r.LockOwner != strings.TrimSpace(workerID) {
		return ErrOutboxLockOwnershipMismatch
	}
	if at.IsZero() {
		return ErrOutboxPublishTimeRequired
	}
	at = at.UTC()
	r.Status = OutboxStatusPublished
	r.PublishedAt = &at
	r.NextAttemptAt = nil
	r.LastError = ""
	r.LockOwner = ""
	r.LockUntil = nil
	return nil
}

type OutboxRetryPolicy struct {
	BaseDelay  time.Duration
	MaxDelay   time.Duration
	Multiplier uint32
}

func DefaultOutboxRetryPolicy() OutboxRetryPolicy {
	return OutboxRetryPolicy{BaseDelay: time.Second, MaxDelay: 5 * time.Minute, Multiplier: 2}
}
func (p OutboxRetryPolicy) Validate() error {
	if p.BaseDelay <= 0 || p.MaxDelay < p.BaseDelay || p.Multiplier < 1 {
		return ErrOutboxInvalidRetrySchedule
	}
	return nil
}
func (p OutboxRetryPolicy) Delay(attempt uint32) time.Duration {
	d := p.BaseDelay
	for i := uint32(1); i < attempt; i++ {
		if d >= p.MaxDelay/time.Duration(p.Multiplier) {
			return p.MaxDelay
		}
		d *= time.Duration(p.Multiplier)
	}
	if d > p.MaxDelay {
		return p.MaxDelay
	}
	return d
}
func (r *OutboxRecord) RegisterFailure(workerID, reason string, failedAt time.Time, policy OutboxRetryPolicy) error {
	if r == nil {
		return ErrOutboxRecordNotFound
	}
	if r.Status == OutboxStatusPublished {
		return ErrOutboxAlreadyPublished
	}
	if r.Status == OutboxStatusDeadLettered {
		return ErrOutboxAlreadyDeadLettered
	}
	if r.LockOwner != strings.TrimSpace(workerID) {
		return ErrOutboxLockOwnershipMismatch
	}
	if failedAt.IsZero() {
		return ErrOutboxFailureTimeRequired
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return ErrOutboxFailureReasonRequired
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	failedAt = failedAt.UTC()
	r.LastError = reason
	r.LastAttemptAt = &failedAt
	r.LockOwner = ""
	r.LockUntil = nil
	if r.Attempts >= r.MaxAttempts {
		r.Status = OutboxStatusDeadLettered
		r.DeadLetteredAt = &failedAt
		r.NextAttemptAt = nil
		return nil
	}
	next := failedAt.Add(policy.Delay(r.Attempts))
	r.Status = OutboxStatusRetryScheduled
	r.NextAttemptAt = &next
	return nil
}
func (r OutboxRecord) Ready(at time.Time) bool {
	if r.Status == OutboxStatusPending {
		return true
	}
	return r.Status == OutboxStatusRetryScheduled && r.NextAttemptAt != nil && !r.NextAttemptAt.After(at)
}

type OutboxClaimRequest struct {
	WorkerID     string
	Limit        int
	ClaimedAt    time.Time
	LockDuration time.Duration
}

func (r OutboxClaimRequest) Validate() error {
	if strings.TrimSpace(r.WorkerID) == "" {
		return ErrOutboxWorkerIDRequired
	}
	if r.Limit <= 0 {
		return ErrOutboxClaimLimitInvalid
	}
	if r.ClaimedAt.IsZero() {
		return ErrOutboxPublishTimeRequired
	}
	if r.LockDuration <= 0 {
		return ErrOutboxLockDurationInvalid
	}
	return nil
}

type OutboxRepository interface {
	Insert(context.Context, *sql.Tx, []OutboxRecord) error
	ClaimReady(context.Context, OutboxClaimRequest) ([]OutboxRecord, error)
	MarkPublished(context.Context, uuid.UUID, string, time.Time) error
	ScheduleRetry(context.Context, OutboxRecord, string) error
	MarkDeadLettered(context.Context, OutboxRecord, string) error
	ReleaseExpiredLocks(context.Context, time.Time) (int64, error)
	FindByID(context.Context, uuid.UUID) (OutboxRecord, error)
}
