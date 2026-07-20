package evaluation

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBuildOutboxRecords(t *testing.T) {
	now := time.Now().UTC()
	agg, err := NewEvaluation(uuid.New(), uuid.New(), now)
	if err != nil {
		t.Fatal(err)
	}
	records, err := agg.BuildOutboxRecords(now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	r := records[0]
	if r.EventType != "EvaluationCreatedEvent" || r.AggregateID != agg.ID() || r.Status != OutboxStatusPending {
		t.Fatalf("unexpected record: %+v", r)
	}
}
func TestOutboxRetryAndDeadLetter(t *testing.T) {
	r := OutboxRecord{ID: uuid.New(), Status: OutboxStatusPending, MaxAttempts: 2}
	now := time.Now().UTC()
	if err := r.StartPublishing("w", now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterFailure("w", "boom", now.Add(time.Second), DefaultOutboxRetryPolicy()); err != nil {
		t.Fatal(err)
	}
	if r.Status != OutboxStatusRetryScheduled || r.NextAttemptAt == nil {
		t.Fatalf("expected retry: %+v", r)
	}
	if err := r.StartPublishing("w", *r.NextAttemptAt, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterFailure("w", "boom2", r.NextAttemptAt.Add(time.Second), DefaultOutboxRetryPolicy()); err != nil {
		t.Fatal(err)
	}
	if r.Status != OutboxStatusDeadLettered || r.DeadLetteredAt == nil {
		t.Fatalf("expected dead letter: %+v", r)
	}
}

type memoryOutboxRepo struct {
	mu      sync.Mutex
	records map[uuid.UUID]OutboxRecord
}

func newMemoryOutboxRepo(records ...OutboxRecord) *memoryOutboxRepo {
	m := &memoryOutboxRepo{records: map[uuid.UUID]OutboxRecord{}}
	for _, r := range records {
		m.records[r.ID] = normalizeOutboxRecord(r)
	}
	return m
}
func (m *memoryOutboxRepo) Insert(_ context.Context, _ *sql.Tx, records []OutboxRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range records {
		m.records[r.ID] = normalizeOutboxRecord(r)
	}
	return nil
}
func (m *memoryOutboxRepo) ClaimReady(_ context.Context, req OutboxClaimRequest) ([]OutboxRecord, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []OutboxRecord{}
	for id, r := range m.records {
		if len(out) >= req.Limit {
			break
		}
		if !r.Ready(req.ClaimedAt) {
			continue
		}
		if err := r.StartPublishing(req.WorkerID, req.ClaimedAt, req.LockDuration); err != nil {
			return nil, err
		}
		m.records[id] = r
		out = append(out, r)
	}
	return out, nil
}
func (m *memoryOutboxRepo) MarkPublished(_ context.Context, id uuid.UUID, w string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return ErrOutboxRecordNotFound
	}
	if err := r.MarkPublished(w, at); err != nil {
		return err
	}
	m.records[id] = r
	return nil
}
func (m *memoryOutboxRepo) ScheduleRetry(_ context.Context, r OutboxRecord, w string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.records[r.ID]
	if !ok {
		return ErrOutboxRecordNotFound
	}
	if old.LockOwner != w {
		return ErrOutboxLockOwnershipMismatch
	}
	m.records[r.ID] = r
	return nil
}
func (m *memoryOutboxRepo) MarkDeadLettered(ctx context.Context, r OutboxRecord, w string) error {
	return m.ScheduleRetry(ctx, r, w)
}
func (m *memoryOutboxRepo) ReleaseExpiredLocks(_ context.Context, at time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for id, r := range m.records {
		if r.Status == OutboxStatusPublishing && r.LockUntil != nil && !r.LockUntil.After(at) {
			r.Status = OutboxStatusRetryScheduled
			r.LockOwner = ""
			r.LockUntil = nil
			next := at
			r.NextAttemptAt = &next
			m.records[id] = r
			n++
		}
	}
	return n, nil
}
func (m *memoryOutboxRepo) FindByID(_ context.Context, id uuid.UUID) (OutboxRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return OutboxRecord{}, ErrOutboxRecordNotFound
	}
	return r, nil
}

type testBroker struct {
	err      error
	messages []BrokerMessage
	closed   bool
}

func (b *testBroker) Publish(_ context.Context, m BrokerMessage) error {
	if b.err != nil {
		return b.err
	}
	b.messages = append(b.messages, m)
	return nil
}
func (b *testBroker) Close() error { b.closed = true; return nil }
func TestPublisherPublishesAndMarksRecord(t *testing.T) {
	now := time.Now().UTC()
	event := EvaluationCreatedEvent{uuid.New(), uuid.New(), now, 1}
	r, err := NewOutboxRecord(event, now)
	if err != nil {
		t.Fatal(err)
	}
	repo := newMemoryOutboxRepo(r)
	broker := &testBroker{}
	cfg := DefaultOutboxPublisherConfig("worker")
	p, err := NewOutboxPublisher(repo, broker, cfg)
	if err != nil {
		t.Fatal(err)
	}
	n, err := p.PublishOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(broker.messages) != 1 {
		t.Fatalf("expected one publication")
	}
	stored, _ := repo.FindByID(context.Background(), r.ID)
	if stored.Status != OutboxStatusPublished {
		t.Fatalf("status=%s", stored.Status)
	}
}
func TestPublisherSchedulesRetry(t *testing.T) {
	now := time.Now().UTC()
	r, err := NewOutboxRecord(EvaluationCreatedEvent{uuid.New(), uuid.New(), now, 1}, now)
	if err != nil {
		t.Fatal(err)
	}
	repo := newMemoryOutboxRepo(r)
	broker := &testBroker{err: errors.New("broker down")}
	p, _ := NewOutboxPublisher(repo, broker, DefaultOutboxPublisherConfig("worker"))
	n, err := p.PublishOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("published=%d", n)
	}
	stored, _ := repo.FindByID(context.Background(), r.ID)
	if stored.Status != OutboxStatusRetryScheduled || stored.LastError == "" {
		t.Fatalf("unexpected retry state: %+v", stored)
	}
}

func TestBuildOutboxRecordsAfterRuleOutcome(t *testing.T) {
	now := time.Now().UTC()
	agg, err := NewEvaluation(uuid.New(), uuid.New(), now)
	if err != nil {
		t.Fatal(err)
	}
	if err = agg.Start(now); err != nil {
		t.Fatal(err)
	}
	if err = agg.RecordRuleOutcome(RuleOutcome{RuleID: "weight", Status: RuleOutcomePass, EvaluatedAt: now}); err != nil {
		t.Fatal(err)
	}
	records, err := agg.BuildOutboxRecords(now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[1].EventType != "RuleOutcomeRecordedEvent" {
		t.Fatalf("unexpected records: %#v", records)
	}
}
