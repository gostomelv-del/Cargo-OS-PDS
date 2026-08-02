package responsibility

import (
	"errors"
	"testing"
	"time"
)

func responsibilityFixture(t *testing.T) (*Aggregate, time.Time) {
	t.Helper()
	objectID, err := NewPhysicalObjectID("parcel-42")
	if err != nil {
		t.Fatal(err)
	}
	participantID, err := NewParticipantID("vehicle-7")
	if err != nil {
		t.Fatal(err)
	}
	assignedAt := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	aggregate, err := New(objectID, participantID, assignedAt)
	if err != nil {
		t.Fatal(err)
	}
	return aggregate, assignedAt
}

func TestResponsibilityAlwaysHasOneObjectAndParticipant(t *testing.T) {
	aggregate, assignedAt := responsibilityFixture(t)
	snapshot := aggregate.Snapshot()
	if snapshot.ObjectID != "parcel-42" || snapshot.ParticipantID != "vehicle-7" ||
		snapshot.Version != 1 || !snapshot.AssignedAt.Equal(assignedAt) {
		t.Fatalf("unexpected initial responsibility: %#v", snapshot)
	}
	if _, err := New("", "vehicle-7", assignedAt); !errors.Is(err, ErrObjectIDRequired) {
		t.Fatalf("expected missing Object rejection, got %v", err)
	}
	if _, err := New("parcel-42", "", assignedAt); !errors.Is(err, ErrParticipantIDRequired) {
		t.Fatalf("expected missing Participant rejection, got %v", err)
	}
}

func TestTransferAtomicallyReplacesSoleParticipant(t *testing.T) {
	aggregate, assignedAt := responsibilityFixture(t)
	transferredAt := assignedAt.Add(time.Minute)
	if err := aggregate.Transfer("warehouse-3", transferredAt); err != nil {
		t.Fatal(err)
	}
	snapshot := aggregate.Snapshot()
	if snapshot.ParticipantID != "warehouse-3" || snapshot.Version != 2 || !snapshot.AssignedAt.Equal(transferredAt) {
		t.Fatalf("unexpected transferred responsibility: %#v", snapshot)
	}
	events := aggregate.PendingEvents()
	if len(events) != 1 || events[0].FromParticipantID != "vehicle-7" ||
		events[0].ToParticipantID != "warehouse-3" || events[0].Version != 2 {
		t.Fatalf("unexpected transfer event: %#v", events)
	}
}

func TestRejectedTransferLeavesAssignmentUnchanged(t *testing.T) {
	aggregate, assignedAt := responsibilityFixture(t)
	before := aggregate.Snapshot()
	cases := []struct {
		name string
		to   ParticipantID
		at   time.Time
		want error
	}{
		{"missing target", "", assignedAt.Add(time.Minute), ErrParticipantIDRequired},
		{"same target", "vehicle-7", assignedAt.Add(time.Minute), ErrSameParticipant},
		{"same time", "warehouse-3", assignedAt, ErrTransferTime},
		{"earlier time", "warehouse-3", assignedAt.Add(-time.Second), ErrTransferTime},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := aggregate.Transfer(test.to, test.at); !errors.Is(err, test.want) {
				t.Fatalf("expected %v, got %v", test.want, err)
			}
			if snapshot := aggregate.Snapshot(); snapshot != before || len(aggregate.PendingEvents()) != 0 {
				t.Fatalf("rejected transfer mutated responsibility: %#v", snapshot)
			}
		})
	}
}

func TestSnapshotRehydratesWithoutPendingEvents(t *testing.T) {
	aggregate, assignedAt := responsibilityFixture(t)
	if err := aggregate.Transfer("warehouse-3", assignedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	restored, err := Rehydrate(aggregate.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if restored.Snapshot() != aggregate.Snapshot() || len(restored.PendingEvents()) != 0 {
		t.Fatal("rehydration changed responsibility or recreated events")
	}
}

func TestPendingEventsAreDefensiveCopies(t *testing.T) {
	aggregate, assignedAt := responsibilityFixture(t)
	if err := aggregate.Transfer("warehouse-3", assignedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	first := aggregate.PendingEvents()
	first[0].ToParticipantID = "modified"
	if aggregate.PendingEvents()[0].ToParticipantID != "warehouse-3" {
		t.Fatal("pending events leaked mutable aggregate state")
	}
	aggregate.ClearPendingEvents()
	if len(aggregate.PendingEvents()) != 0 || aggregate.Snapshot().ParticipantID != "warehouse-3" {
		t.Fatal("clearing events changed current responsibility")
	}
}
