package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunRequiresDatabaseURL(t *testing.T) {
	t.Setenv("PDS_DATABASE_URL", "")
	if err := run(); !errors.Is(err, errDatabaseURLRequired) {
		t.Fatalf("expected database URL error, got %v", err)
	}
}

func TestParseLifecycleRequest(t *testing.T) {
	request, err := parseLifecycleRequest([]string{
		"SuSpEnD", " cargo-transfer ", " 1.0.0 ", "2026-07-26T10:30:00+02:00",
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.Action != actionSuspend ||
		request.PolicyID != "cargo-transfer" ||
		request.Version != "1.0.0" ||
		request.EventAt.Format(time.RFC3339) != "2026-07-26T08:30:00Z" {
		t.Fatalf("unexpected request: %#v", request)
	}

	invalid := [][]string{
		nil,
		{"delete", "cargo-transfer", "1.0.0", "2026-07-26T10:30:00Z"},
		{"suspend", "", "1.0.0", "2026-07-26T10:30:00Z"},
		{"retire", "cargo-transfer", "", "2026-07-26T10:30:00Z"},
		{"retire", "cargo-transfer", "1.0.0", "now"},
	}
	for _, args := range invalid {
		if _, err = parseLifecycleRequest(args); !errors.Is(err, errLifecycleUsage) {
			t.Fatalf("invalid arguments were accepted: %#v, %v", args, err)
		}
	}
}

func TestExecuteLifecycleRequestDispatchesExactTransition(t *testing.T) {
	at := time.Date(2026, 7, 26, 8, 30, 0, 0, time.UTC)
	for _, action := range []lifecycleAction{actionSuspend, actionRetire} {
		store := &recordingLifecycleStore{}
		request := lifecycleRequest{
			Action: action, PolicyID: "cargo-transfer", Version: "1.0.0", EventAt: at,
		}
		if err := executeLifecycleRequest(context.Background(), store, request); err != nil {
			t.Fatal(err)
		}
		if store.action != action || store.policyID != request.PolicyID ||
			store.version != request.Version || !store.at.Equal(at) {
			t.Fatalf("wrong transition dispatched: %#v", store)
		}
	}
}

func TestExecuteLifecycleRequestPropagatesStoreFailure(t *testing.T) {
	target := errors.New("transition rejected")
	store := &recordingLifecycleStore{err: target}
	err := executeLifecycleRequest(context.Background(), store, lifecycleRequest{
		Action: actionSuspend, PolicyID: "cargo-transfer", Version: "1.0.0", EventAt: time.Now(),
	})
	if !errors.Is(err, target) {
		t.Fatalf("expected store error, got %v", err)
	}
}

type recordingLifecycleStore struct {
	action            lifecycleAction
	policyID, version string
	at                time.Time
	err               error
}

func (s *recordingLifecycleStore) Suspend(_ context.Context, policyID, version string, at time.Time) error {
	s.action, s.policyID, s.version, s.at = actionSuspend, policyID, version, at
	return s.err
}

func (s *recordingLifecycleStore) Retire(_ context.Context, policyID, version string, at time.Time) error {
	s.action, s.policyID, s.version, s.at = actionRetire, policyID, version, at
	return s.err
}
