package evaluation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrOutboxPublisherUnavailable    = errors.New("evaluation: outbox publisher unavailable")
	ErrOutboxBrokerUnavailable       = errors.New("evaluation: message broker unavailable")
	ErrOutboxPublisherAlreadyRunning = errors.New("evaluation: outbox publisher already running")
	ErrOutboxPublisherNotRunning     = errors.New("evaluation: outbox publisher is not running")
	ErrOutboxPublisherConfigInvalid  = errors.New("evaluation: invalid outbox publisher configuration")
)

type BrokerMessage struct {
	ID, Topic, Key string
	Headers        map[string]string
	Payload        []byte
	OccurredAt     time.Time
}
type MessageBroker interface {
	Publish(context.Context, BrokerMessage) error
	Close() error
}
type MessageBrokerHealth interface{ Ping(context.Context) error }
type OutboxPublisherRepository interface {
	ClaimReady(context.Context, OutboxClaimRequest) ([]OutboxRecord, error)
	MarkPublished(context.Context, uuid.UUID, string, time.Time) error
	ScheduleRetry(context.Context, OutboxRecord, string) error
	MarkDeadLettered(context.Context, OutboxRecord, string) error
	ReleaseExpiredLocks(context.Context, time.Time) (int64, error)
}
type OutboxPublisherConfig struct {
	WorkerID, Topic                            string
	BatchSize                                  int
	PollInterval, LockDuration, PublishTimeout time.Duration
	MaxParallelPublications                    int
	RetryPolicy                                OutboxRetryPolicy
	ExpiredLockCleanupInterval                 time.Duration
}

func DefaultOutboxPublisherConfig(workerID string) OutboxPublisherConfig {
	return OutboxPublisherConfig{workerID, "cargoos.evaluation.events.v1", 100, 500 * time.Millisecond, 30 * time.Second, 10 * time.Second, 8, DefaultOutboxRetryPolicy(), 30 * time.Second}
}
func (c OutboxPublisherConfig) Validate() error {
	if strings.TrimSpace(c.WorkerID) == "" {
		return ErrOutboxWorkerIDRequired
	}
	if strings.TrimSpace(c.Topic) == "" || c.PollInterval <= 0 || c.LockDuration <= 0 || c.PublishTimeout <= 0 || c.MaxParallelPublications <= 0 || c.ExpiredLockCleanupInterval <= 0 {
		return ErrOutboxPublisherConfigInvalid
	}
	if c.BatchSize <= 0 {
		return ErrOutboxClaimLimitInvalid
	}
	if c.PublishTimeout >= c.LockDuration {
		return fmt.Errorf("%w: publish timeout must be shorter than lock duration", ErrOutboxPublisherConfigInvalid)
	}
	return c.RetryPolicy.Validate()
}

type OutboxPublisher struct {
	repo    OutboxPublisherRepository
	broker  MessageBroker
	config  OutboxPublisherConfig
	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func NewOutboxPublisher(repo OutboxPublisherRepository, broker MessageBroker, c OutboxPublisherConfig) (*OutboxPublisher, error) {
	if repo == nil {
		return nil, ErrOutboxPublisherUnavailable
	}
	if broker == nil {
		return nil, ErrOutboxBrokerUnavailable
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &OutboxPublisher{repo: repo, broker: broker, config: c}, nil
}
func (p *OutboxPublisher) PublishOnce(ctx context.Context) (int, error) {
	records, err := p.repo.ClaimReady(ctx, OutboxClaimRequest{p.config.WorkerID, p.config.BatchSize, time.Now().UTC(), p.config.LockDuration})
	if err != nil {
		return 0, err
	}
	published := 0
	for i := range records {
		r := records[i]
		pc, cancel := context.WithTimeout(ctx, p.config.PublishTimeout)
		err = p.broker.Publish(pc, BrokerMessage{ID: r.ID.String(), Topic: p.config.Topic, Key: r.AggregateID.String(), Headers: map[string]string{"event_type": r.EventType, "aggregate_version": fmt.Sprint(r.AggregateVersion)}, Payload: append([]byte(nil), r.Payload...), OccurredAt: r.OccurredAt})
		cancel()
		now := time.Now().UTC()
		if err == nil {
			if err = p.repo.MarkPublished(ctx, r.ID, p.config.WorkerID, now); err != nil {
				return published, err
			}
			published++
			continue
		}
		if ferr := r.RegisterFailure(p.config.WorkerID, err.Error(), now, p.config.RetryPolicy); ferr != nil {
			return published, ferr
		}
		if r.Status == OutboxStatusDeadLettered {
			err = p.repo.MarkDeadLettered(ctx, r, p.config.WorkerID)
		} else {
			err = p.repo.ScheduleRetry(ctx, r, p.config.WorkerID)
		}
		if err != nil {
			return published, err
		}
	}
	return published, nil
}
func (p *OutboxPublisher) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return ErrOutboxPublisherAlreadyRunning
	}
	runCtx, cancel := context.WithCancel(ctx)
	p.running = true
	p.cancel = cancel
	p.wg.Add(1)
	p.mu.Unlock()
	go func() {
		defer p.wg.Done()
		ticker := time.NewTicker(p.config.PollInterval)
		cleanup := time.NewTicker(p.config.ExpiredLockCleanupInterval)
		defer ticker.Stop()
		defer cleanup.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				_, _ = p.PublishOnce(runCtx)
			case t := <-cleanup.C:
				_, _ = p.repo.ReleaseExpiredLocks(runCtx, t.UTC())
			}
		}
	}()
	return nil
}
func (p *OutboxPublisher) Stop() error {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return ErrOutboxPublisherNotRunning
	}
	p.cancel()
	p.running = false
	p.mu.Unlock()
	p.wg.Wait()
	return p.broker.Close()
}
