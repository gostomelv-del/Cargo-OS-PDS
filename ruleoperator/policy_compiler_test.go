package ruleoperator

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"cargoos/evidence"
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

func TestPolicyDocumentCompilerValidatesEveryRequiredRule(t *testing.T) {
	version := policyVersion(t, PolicyDocumentSchemaV1, `{
	"evidence_qualification":{"version":"qualification.v1"},
	"rules":[
		{"rule_id":"valid","operator":"EXISTENCE","evidence_type":"IMAGE","minimum_count":1},
		{"rule_id":"invalid","operator":"MATCH","selector":{"evidence_type":"WEIGHT"}}
	]}`, "valid", "invalid")
	err := (PolicyDocumentCompiler{}).ValidatePolicyDocument(context.Background(), version)
	if !errors.Is(err, ErrInvalidPolicyDocument) {
		t.Fatalf("got %v, want %v", err, ErrInvalidPolicyDocument)
	}
}

func TestPolicyDocumentCompilerCompilesEvidenceQualification(t *testing.T) {
	version := policyVersion(t, PolicyDocumentSchemaV1, `{
		"evidence_qualification":{
			"version":"qualification.v1",
			"trusted_sources":["scale-17"],
			"allowed_types":["WEIGHT"],
			"allowed_acquisition_methods":["HTTP"],
			"max_age":"5m",
			"future_tolerance":"2s",
			"require_confidence":true,
			"minimum_confidence":0.8,
			"required_provenance":["device_id"],
			"required_payload_fields":["value"]
		},
		"rules":[{"rule_id":"weight","operator":"EXISTENCE","evidence_type":"WEIGHT","minimum_count":1}]
	}`, "weight")
	compiled, err := (PolicyDocumentCompiler{}).CompileQualificationPolicy(context.Background(), version)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Version != "qualification.v1" ||
		!compiled.TrustedSources["scale-17"] ||
		!compiled.AllowedTypes[evidence.TypeWeight] ||
		!compiled.AllowedAcquisitionMethods["HTTP"] ||
		compiled.MaxAge != 5*time.Minute ||
		compiled.FutureTolerance != 2*time.Second ||
		!compiled.RequireConfidence ||
		compiled.MinimumConfidence == nil ||
		*compiled.MinimumConfidence != 0.8 {
		t.Fatalf("unexpected qualification policy: %#v", compiled)
	}
}

func TestPolicyDocumentCompilerRejectsInvalidEvidenceQualification(t *testing.T) {
	tests := []string{
		`{"rules":[{"rule_id":"weight","operator":"EXISTENCE","evidence_type":"WEIGHT","minimum_count":1}]}`,
		`{"evidence_qualification":{"version":"","max_age":"5m"},"rules":[{"rule_id":"weight","operator":"EXISTENCE","evidence_type":"WEIGHT","minimum_count":1}]}`,
		`{"evidence_qualification":{"version":"qualification.v1","max_age":"later"},"rules":[{"rule_id":"weight","operator":"EXISTENCE","evidence_type":"WEIGHT","minimum_count":1}]}`,
		`{"evidence_qualification":{"version":"qualification.v1","trusted_sources":["scale","scale"]},"rules":[{"rule_id":"weight","operator":"EXISTENCE","evidence_type":"WEIGHT","minimum_count":1}]}`,
		`{"evidence_qualification":{"version":"qualification.v1","minimum_confidence":2},"rules":[{"rule_id":"weight","operator":"EXISTENCE","evidence_type":"WEIGHT","minimum_count":1}]}`,
	}
	for _, document := range tests {
		version := policyVersion(t, PolicyDocumentSchemaV1, document, "weight")
		if _, err := (PolicyDocumentCompiler{}).CompileQualificationPolicy(context.Background(), version); !errors.Is(err, ErrInvalidPolicyDocument) {
			t.Fatalf("got %v, want %v for %s", err, ErrInvalidPolicyDocument, document)
		}
	}
}

func TestPolicyDocumentCompilerRejectsRuleOutsideQualificationScope(t *testing.T) {
	tests := []string{
		`{
			"evidence_qualification":{
				"version":"qualification.v1",
				"allowed_types":["IMAGE"]
			},
			"rules":[{
				"rule_id":"weight",
				"operator":"MATCH",
				"selector":{"evidence_type":"WEIGHT"},
				"expected":25
			}]
		}`,
		`{
			"evidence_qualification":{
				"version":"qualification.v1",
				"trusted_sources":["scale-allowed"],
				"allowed_types":["WEIGHT"]
			},
			"rules":[{
				"rule_id":"weight",
				"operator":"RANGE",
				"selector":{"evidence_type":"WEIGHT","source_id":"scale-denied"},
				"minimum":"20",
				"maximum":"30"
			}]
		}`,
		`{
			"evidence_qualification":{
				"version":"qualification.v1",
				"trusted_sources":["source"],
				"allowed_types":["CONTACT"]
			},
			"rules":[{
				"rule_id":"flow",
				"operator":"SEQUENCE",
				"steps":[
					{"selector":{"evidence_type":"CONTACT","source_id":"source"},"expected":true},
					{"selector":{"evidence_type":"POSITION","source_id":"source"},"expected":true}
				]
			}]
		}`,
	}
	for _, document := range tests {
		version := policyVersion(t, PolicyDocumentSchemaV1, document,
			ruleIDFromDocument(t, document))
		err := (PolicyDocumentCompiler{}).ValidatePolicyDocument(context.Background(), version)
		if !errors.Is(err, ErrRuleOutsideQualificationScope) {
			t.Fatalf("got %v, want %v", err, ErrRuleOutsideQualificationScope)
		}
	}
}

func ruleIDFromDocument(t *testing.T, document string) string {
	t.Helper()
	var decoded struct {
		Rules []struct {
			RuleID string `json:"rule_id"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(document), &decoded); err != nil || len(decoded.Rules) != 1 {
		t.Fatalf("invalid test document: %v", err)
	}
	return decoded.Rules[0].RuleID
}
