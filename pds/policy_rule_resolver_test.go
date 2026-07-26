package pds

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"cargoos/evaluation"
	"cargoos/policy"
)

type recordingVersionReader struct {
	version *policy.Version
	err     error
	calls   []PolicyRuleReference
}

func (r *recordingVersionReader) FindVersion(
	_ context.Context,
	policyID string,
	version string,
	hash string,
) (*policy.Version, error) {
	r.calls = append(r.calls, PolicyRuleReference{
		PolicyID: policyID, PolicyVersion: version, PolicyHash: hash,
	})
	return r.version, r.err
}

type recordingPolicyRuleCompiler struct {
	version *policy.Version
	ruleID  string
	calls   int
	result  RuleOperator
	err     error
}

func (c *recordingPolicyRuleCompiler) CompileRule(
	_ context.Context,
	version *policy.Version,
	ruleID string,
) (RuleOperator, error) {
	c.calls++
	c.version = version
	c.ruleID = ruleID
	return c.result, c.err
}

func resolverPolicyVersion(t *testing.T) *policy.Version {
	t.Helper()
	version, err := policy.NewVersion(policy.Input{
		PolicyID: "cargo-transfer", Version: "1.0.0", SchemaVersion: "policy.v1",
		EffectiveFrom:   time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
		RequiredRuleIDs: []string{"weight"},
		Document:        json.RawMessage(`{"rules":[{"rule_id":"weight","operator":"RANGE"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return version
}

func TestPolicyDocumentRuleResolverCompilesExactBoundVersion(t *testing.T) {
	version := resolverPolicyVersion(t)
	snapshot := version.Snapshot()
	operator := &testRuleOperator{id: "weight", decision: RuleDecision{Status: evaluation.RuleOutcomePass}}
	reader := &recordingVersionReader{version: version}
	compiler := &recordingPolicyRuleCompiler{result: operator}
	resolver, err := NewPolicyDocumentRuleResolver(reader, compiler)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolveRuleOperator(context.Background(), PolicyRuleReference{
		PolicyID: snapshot.PolicyID, PolicyVersion: snapshot.Version,
		PolicyHash: snapshot.Hash, RuleID: "weight",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved != operator || compiler.calls != 1 || compiler.version != version || compiler.ruleID != "weight" {
		t.Fatal("compiler did not receive the exact immutable policy and rule")
	}
	if len(reader.calls) != 1 ||
		reader.calls[0].PolicyID != snapshot.PolicyID ||
		reader.calls[0].PolicyVersion != snapshot.Version ||
		reader.calls[0].PolicyHash != snapshot.Hash {
		t.Fatalf("wrong exact policy lookup: %#v", reader.calls)
	}
}

func TestPolicyDocumentRuleResolverDoesNotCompileFailedExactLookup(t *testing.T) {
	reader := &recordingVersionReader{err: policy.ErrPolicyNotFound}
	compiler := &recordingPolicyRuleCompiler{}
	resolver, _ := NewPolicyDocumentRuleResolver(reader, compiler)
	_, err := resolver.ResolveRuleOperator(context.Background(), PolicyRuleReference{
		PolicyID: "cargo-transfer", PolicyVersion: "1.0.0",
		PolicyHash: "sha256:wrong", RuleID: "weight",
	})
	if !errors.Is(err, policy.ErrPolicyNotFound) {
		t.Fatalf("expected exact lookup failure, got %v", err)
	}
	if compiler.calls != 0 {
		t.Fatal("compiler received a policy after exact lookup failure")
	}
}

func TestPolicyDocumentRuleResolverRejectsDependenciesAndSubstitution(t *testing.T) {
	compiler := &recordingPolicyRuleCompiler{}
	if _, err := NewPolicyDocumentRuleResolver(nil, compiler); !errors.Is(err, ErrPolicyVersionReaderRequired) {
		t.Fatalf("expected reader requirement, got %v", err)
	}
	version := resolverPolicyVersion(t)
	reader := &recordingVersionReader{version: version}
	if _, err := NewPolicyDocumentRuleResolver(reader, nil); !errors.Is(err, ErrPolicyRuleCompilerRequired) {
		t.Fatalf("expected compiler requirement, got %v", err)
	}
	compiler.result = &testRuleOperator{id: "different-rule"}
	resolver, _ := NewPolicyDocumentRuleResolver(reader, compiler)
	snapshot := version.Snapshot()
	if _, err := resolver.ResolveRuleOperator(context.Background(), PolicyRuleReference{
		PolicyID: snapshot.PolicyID, PolicyVersion: snapshot.Version,
		PolicyHash: snapshot.Hash, RuleID: "weight",
	}); !errors.Is(err, ErrResolvedRuleMismatch) {
		t.Fatalf("expected compiled identity rejection, got %v", err)
	}
}
