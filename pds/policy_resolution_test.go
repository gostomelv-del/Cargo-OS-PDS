package pds

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/policy"
)

func resolutionRegistry(t *testing.T, from time.Time, rules []string) *policy.Registry {
	t.Helper()
	version, err := policy.NewVersion(policy.Input{
		PolicyID: "cargo-transfer", Version: "1.0.0", SchemaVersion: "policy.v1",
		EffectiveFrom: from, RequiredRuleIDs: rules, Document: json.RawMessage(`{"mode":"strict"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := policy.NewRegistry()
	if err = registry.Add(context.Background(), version); err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestResolveAndBindPolicyUsesEvaluationCreationTime(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	service := NewServiceWithStore(store, func() time.Time { return now })
	created, err := service.Create(context.Background(), uuid.New(), []string{"weight", "support-sequence"})
	if err != nil {
		t.Fatal(err)
	}
	registry := resolutionRegistry(t, now.Add(-time.Hour), created.RequiredRuleIDs)
	bound, err := service.ResolveAndBindPolicy(context.Background(), created.EvaluationID, "cargo-transfer", registry)
	if err != nil {
		t.Fatal(err)
	}
	if bound.PolicyBinding == nil || bound.PolicyBinding.PolicyID != "cargo-transfer" || bound.PolicyBinding.Version != "1.0.0" {
		t.Fatalf("resolved policy was not bound: %#v", bound.PolicyBinding)
	}
	trace, err := service.Trace(context.Background(), created.EvaluationID)
	if err != nil || trace.PolicyBinding == nil || trace.PolicyBinding.Hash != bound.PolicyBinding.Hash {
		t.Fatalf("resolved policy missing from trace: %#v, %v", trace, err)
	}
	records := store.OutboxRecords()
	if records[len(records)-1].EventType != "VerificationPolicyBoundEvent" {
		t.Fatalf("policy event missing from outbox: %#v", records)
	}
}

func TestResolveAndBindPolicyRejectsRulePlanMismatch(t *testing.T) {
	now := time.Now().UTC()
	service := NewService(func() time.Time { return now })
	created, _ := service.Create(context.Background(), uuid.New(), []string{"weight"})
	registry := resolutionRegistry(t, now.Add(-time.Hour), []string{"different-rule"})
	if _, err := service.ResolveAndBindPolicy(context.Background(), created.EvaluationID, "cargo-transfer", registry); !errors.Is(err, ErrPolicyRulePlanMismatch) {
		t.Fatalf("expected rule plan error, got %v", err)
	}
}
