package responsibility

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestMemoryRepositoryPersistsVersionedResponsibility(t *testing.T) {
	ctx := context.Background()
	repository := NewMemoryRepository()
	aggregate, assignedAt := responsibilityFixture(t)
	if err := repository.SaveResponsibility(ctx, aggregate.Snapshot(), 0); err != nil {
		t.Fatal(err)
	}
	loaded, err := repository.FindResponsibility(ctx, "parcel-42")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Snapshot() != aggregate.Snapshot() {
		t.Fatalf("stored responsibility changed: %#v", loaded.Snapshot())
	}
	if err = loaded.Transfer("warehouse-3", assignedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = repository.SaveResponsibility(ctx, loaded.Snapshot(), 1); err != nil {
		t.Fatal(err)
	}
	updated, err := repository.FindResponsibility(ctx, "parcel-42")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot := updated.Snapshot(); snapshot.ParticipantID != "warehouse-3" || snapshot.Version != 2 {
		t.Fatalf("unexpected stored transfer: %#v", snapshot)
	}
}

func TestMemoryRepositoryRejectsInvalidVersionTransition(t *testing.T) {
	repository := NewMemoryRepository()
	aggregate, _ := responsibilityFixture(t)
	if err := repository.SaveResponsibility(context.Background(), aggregate.Snapshot(), 1); !errors.Is(err, ErrInvalidVersionTransition) {
		t.Fatalf("expected invalid transition, got %v", err)
	}
}

func TestMemoryRepositoryRejectsSnapshotThatIsNotATransfer(t *testing.T) {
	ctx := context.Background()
	repository := NewMemoryRepository()
	aggregate, assignedAt := responsibilityFixture(t)
	if err := repository.SaveResponsibility(ctx, aggregate.Snapshot(), 0); err != nil {
		t.Fatal(err)
	}
	invalid := aggregate.Snapshot()
	invalid.Version = 2
	invalid.AssignedAt = assignedAt.Add(-time.Second)
	if err := repository.SaveResponsibility(ctx, invalid, 1); !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("expected invalid persisted transfer conflict, got %v", err)
	}
}

func TestMemoryRepositoryRejectsStaleWriter(t *testing.T) {
	ctx := context.Background()
	repository := NewMemoryRepository()
	aggregate, assignedAt := responsibilityFixture(t)
	if err := repository.SaveResponsibility(ctx, aggregate.Snapshot(), 0); err != nil {
		t.Fatal(err)
	}
	first, _ := repository.FindResponsibility(ctx, "parcel-42")
	second, _ := repository.FindResponsibility(ctx, "parcel-42")
	if err := first.Transfer("warehouse-3", assignedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := second.Transfer("hub-9", assignedAt.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var writers sync.WaitGroup
	writers.Add(2)
	for _, candidate := range []*Aggregate{first, second} {
		go func(candidate *Aggregate) {
			defer writers.Done()
			<-start
			results <- repository.SaveResponsibility(ctx, candidate.Snapshot(), 1)
		}(candidate)
	}
	close(start)
	writers.Wait()
	close(results)

	successes, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrConcurrentModification):
			conflicts++
		default:
			t.Fatalf("unexpected save result: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("expected one winner and one conflict, got successes=%d conflicts=%d", successes, conflicts)
	}
	stored, err := repository.FindResponsibility(ctx, "parcel-42")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Snapshot().Version != 2 {
		t.Fatalf("unexpected winning version: %d", stored.Snapshot().Version)
	}
}

func TestMemoryRepositoryNotFound(t *testing.T) {
	_, err := NewMemoryRepository().FindResponsibility(context.Background(), "parcel-404")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}
