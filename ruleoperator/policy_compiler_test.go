package ruleoperator

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"cargoos/policy"
)

func policyVersion(t *testing.T, schema, document string, requiredRules ...string) *policy.Version {
	t.Helper()
	version, err := policy.NewVersion(policy.Input{
		PolicyID: "cargo-transfer", Version: "1.0.0", SchemaVersion: schema,
		EffectiveFrom:   time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC),
		RequiredRuleIDs: requiredRules, Document: json.RawMessage(document),
	})
	if err != nil {
		t.Fatal(err)
	}
	return version
}

func TestPolicyDocumentCompilerCompilesEveryOperator(t *testing.T) {
	document := `{"rules":[
		{"rule_id":"match","operator":"MATCH","selector":{"evidence_type":"WEIGHT","json_pointer":"/unit"},"expected":"kg"},
		{"rule_id":"range","operator":"RANGE","selector":{"evidence_type":"WEIGHT","json_pointer":"/value"},"minimum":"20","maximum":"30"},
		{"rule_id":"tolerance","operator":"TOLERANCE","selector":{"evidence_type":"WEIGHT","json_pointer":"/value"},"expected":25,"tolerance":"0.5"},
		{"rule_id":"existence","operator":"EXISTENCE","evidence_type":"IMAGE","source_id":"camera-1","minimum_count":2},
		{"rule_id":"sequence","operator":"SEQUENCE","steps":[
			{"selector":{"evidence_type":"CONTACT","source_id":"source","json_pointer":"/released"},"expected":true},
			{"selector":{"evidence_type":"CONTACT","source_id":"target","json_pointer":"/confirmed"},"expected":true}
		],"max_gap":"5s","max_duration":"10s"}
	]}`
	version := policyVersion(t, PolicyDocumentSchemaV1, document,
		"match", "range", "tolerance", "existence", "sequence")
	compiler := PolicyDocumentCompiler{}
	for _, ruleID := range version.Snapshot().RequiredRuleIDs {
		operator, err := compiler.CompileRule(context.Background(), version, ruleID)
		if err != nil {
			t.Fatalf("%s: %v", ruleID, err)
		}
		if operator.RuleID() != ruleID {
			t.Fatalf("got rule ID %q, want %q", operator.RuleID(), ruleID)
		}
	}
}

func TestPolicyDocumentCompilerFailsClosed(t *testing.T) {
	tests := []struct {
		name, schema, document, ruleID string
		target                         error
	}{
		{"unsupported schema", "policy.document.v2", `{"rules":[]}`, "weight", ErrUnsupportedPolicySchema},
		{"unknown field", PolicyDocumentSchemaV1, `{"rules":[{"rule_id":"weight","operator":"MATCH","selector":{"evidence_type":"WEIGHT"},"expected":1,"optional":true}]}`, "weight", ErrInvalidPolicyDocument},
		{"unknown operator", PolicyDocumentSchemaV1, `{"rules":[{"rule_id":"weight","operator":"SCRIPT"}]}`, "weight", ErrUnsupportedOperator},
		{"missing rule", PolicyDocumentSchemaV1, `{"rules":[{"rule_id":"seal","operator":"EXISTENCE","evidence_type":"IMAGE","minimum_count":1}]}`, "weight", ErrPolicyRuleNotFound},
		{"duplicate rule", PolicyDocumentSchemaV1, `{"rules":[{"rule_id":"weight","operator":"EXISTENCE","evidence_type":"WEIGHT","minimum_count":1},{"rule_id":"weight","operator":"EXISTENCE","evidence_type":"WEIGHT","minimum_count":1}]}`, "weight", ErrDuplicatePolicyRule},
		{"mixed fields", PolicyDocumentSchemaV1, `{"rules":[{"rule_id":"weight","operator":"MATCH","selector":{"evidence_type":"WEIGHT"},"expected":1,"minimum":"0"}]}`, "weight", ErrInvalidPolicyDocument},
		{"invalid duration", PolicyDocumentSchemaV1, `{"rules":[{"rule_id":"flow","operator":"SEQUENCE","steps":[{"selector":{"evidence_type":"CONTACT"},"expected":true},{"selector":{"evidence_type":"CONTACT"},"expected":false}],"max_gap":"later"}]}`, "flow", ErrInvalidPolicyDocument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			version := policyVersion(t, test.schema, test.document, "weight")
			_, err := (PolicyDocumentCompiler{}).CompileRule(context.Background(), version, test.ruleID)
			if !errors.Is(err, test.target) {
				t.Fatalf("got %v, want %v", err, test.target)
			}
		})
	}
}
