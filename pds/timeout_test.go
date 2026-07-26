package pds

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
)

func TestExpireTimedOutFailsClosed(t *testing.T) {
	createdAt := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	now := createdAt
	store := NewMemoryStore()
	service := NewServiceWithStore(store, func() time.Time { return now })
	created, err := service.Create(context.Background(), uuid.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	policy := TimeoutPolicy{CreatedTimeout: time.Minute, RunningTimeout: 5 * time.Minute}

	now = createdAt.Add(59 * time.Second)
	if _, err = service.ExpireTimedOut(context.Background(), created.EvaluationID, policy); !errors.Is(err, ErrEvaluationNotTimedOut) {
		t.Fatalf("expected not-timed-out error, got %v", err)
	}
	before, err := service.Snapshot(context.Background(), created.EvaluationID)
	if err != nil {
		t.Fatal(err)
	}
	if before.State != evaluation.StateCreated || before.Version != created.Version {
		t.Fatalf("early timeout mutated Evaluation: %#v", before)
	}

	now = createdAt.Add(time.Minute)
	expired, err := service.ExpireTimedOut(context.Background(), created.EvaluationID, policy)
	if err != nil {
		t.Fatal(err)
	}
	if expired.State != evaluation.StateExpired ||
		expired.Result != evaluation.ResultSystemException ||
		expired.ExpiredAt == nil ||
		len(expired.ReasonCodes) != 1 ||
		expired.ReasonCodes[0] != evaluation.ReasonCodeEvaluationTimeout {
		t.Fatalf("unexpected timeout snapshot: %#v", expired)
	}
	records := store.OutboxRecords()
	if len(records) != 2 || records[1].EventType != "EvaluationExpiredEvent" {
		t.Fatalf("expected one timeout event, got %#v", records)
	}
}

func TestExpireTimedOutRetryIsIdempotent(t *testing.T) {
	createdAt := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	now := createdAt
	store := NewMemoryStore()
	service := NewServiceWithStore(store, func() time.Time { return now })
	created, err := service.Create(context.Background(), uuid.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	now = createdAt.Add(time.Minute)
	policy := TimeoutPolicy{CreatedTimeout: time.Minute}
	first, err := service.ExpireTimedOut(context.Background(), created.EvaluationID, policy)
	if err != nil {
		t.Fatal(err)
	}
	eventCount := len(store.OutboxRecords())

	now = now.Add(time.Hour)
	retry, err := service.ExpireTimedOut(context.Background(), created.EvaluationID, policy)
	if err != nil {
		t.Fatal(err)
	}
	if first.Version != retry.Version ||
		first.ExpiredAt == nil || retry.ExpiredAt == nil ||
		!first.ExpiredAt.Equal(*retry.ExpiredAt) ||
		len(store.OutboxRecords()) != eventCount {
		t.Fatalf("timeout retry mutated state: first=%#v retry=%#v", first, retry)
	}
}

func TestRunningTimeoutUsesStartedAt(t *testing.T) {
	createdAt := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	now := createdAt
	service := NewService(func() time.Time { return now })
	created, err := service.Create(context.Background(), uuid.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	now = createdAt.Add(10 * time.Minute)
	started, err := service.Start(context.Background(), created.EvaluationID)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(4 * time.Minute)
	policy := TimeoutPolicy{RunningTimeout: 5 * time.Minute}
	if _, err = service.ExpireTimedOut(context.Background(), created.EvaluationID, policy); !errors.Is(err, ErrEvaluationNotTimedOut) {
		t.Fatalf("expected running Evaluation to remain active, got %v", err)
	}
	now = now.Add(time.Minute)
	expired, err := service.ExpireTimedOut(context.Background(), created.EvaluationID, policy)
	if err != nil {
		t.Fatal(err)
	}
	if started.StartedAt == nil || expired.ExpiredAt == nil ||
		!expired.ExpiredAt.Equal(started.StartedAt.Add(5*time.Minute)) {
		t.Fatalf("running timeout used wrong deadline: started=%v expired=%v", started.StartedAt, expired.ExpiredAt)
	}
}

func TestExpiredEvaluationRecoversFromStore(t *testing.T) {
	createdAt := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	now := createdAt
	store := NewMemoryStore()
	service := NewServiceWithStore(store, func() time.Time { return now })
	created, err := service.Create(context.Background(), uuid.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	now = createdAt.Add(time.Minute)
	expired, err := service.ExpireTimedOut(
		context.Background(),
		created.EvaluationID,
		TimeoutPolicy{CreatedTimeout: time.Minute},
	)
	if err != nil {
		t.Fatal(err)
	}

	restarted := NewServiceWithStore(store, func() time.Time { return now.Add(time.Hour) })
	recovered, err := restarted.Snapshot(context.Background(), created.EvaluationID)
	if err != nil {
		t.Fatal(err)
	}
	trace, err := restarted.Trace(context.Background(), created.EvaluationID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.State != evaluation.StateExpired ||
		recovered.Version != expired.Version ||
		recovered.ExpiredAt == nil || expired.ExpiredAt == nil ||
		!recovered.ExpiredAt.Equal(*expired.ExpiredAt) ||
		trace.ExpiredAt == nil ||
		!trace.ExpiredAt.Equal(*expired.ExpiredAt) ||
		len(trace.ReasonCodes) != 1 ||
		trace.ReasonCodes[0] != evaluation.ReasonCodeEvaluationTimeout {
		t.Fatalf("recovered timeout state changed: snapshot=%#v trace=%#v", recovered, trace)
	}
}

func TestTimeoutPolicyValidation(t *testing.T) {
	for _, policy := range []TimeoutPolicy{
		{},
		{CreatedTimeout: -time.Second},
		{RunningTimeout: -time.Second},
	} {
		if err := policy.Validate(); !errors.Is(err, ErrTimeoutPolicyInvalid) {
			t.Fatalf("expected invalid policy for %#v, got %v", policy, err)
		}
	}
}
