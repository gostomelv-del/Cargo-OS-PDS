package ruleoperator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"cargoos/evidence"
	"cargoos/pds"
	"cargoos/policy"
)

const PolicyDocumentSchemaV1 = "policy.document.v1"

var (
	ErrUnsupportedPolicySchema = errors.New("ruleoperator: unsupported policy document schema")
	ErrInvalidPolicyDocument   = errors.New("ruleoperator: invalid policy document")
	ErrPolicyRuleNotFound      = errors.New("ruleoperator: policy rule not found")
	ErrDuplicatePolicyRule     = errors.New("ruleoperator: duplicate policy rule")
	ErrUnsupportedOperator     = errors.New("ruleoperator: unsupported operator")
)

// PolicyDocumentCompiler compiles the strict policy.document.v1 representation.
// Unknown fields and operator-inapplicable fields are rejected.
type PolicyDocumentCompiler struct{}

type policyDocumentV1 struct {
	EvidenceQualification *evidenceQualificationV1 `json:"evidence_qualification,omitempty"`
	Rules                 []policyRuleV1           `json:"rules"`
}

type evidenceQualificationV1 struct {
	Version                   string          `json:"version"`
	TrustedSources            []string        `json:"trusted_sources,omitempty"`
	AllowedTypes              []evidence.Type `json:"allowed_types,omitempty"`
	AllowedAcquisitionMethods []string        `json:"allowed_acquisition_methods,omitempty"`
	MaxAge                    *string         `json:"max_age,omitempty"`
	FutureTolerance           *string         `json:"future_tolerance,omitempty"`
	RequireConfidence         bool            `json:"require_confidence,omitempty"`
	MinimumConfidence         *float64        `json:"minimum_confidence,omitempty"`
	RequiredProvenance        []string        `json:"required_provenance,omitempty"`
	RequiredPayloadFields     []string        `json:"required_payload_fields,omitempty"`
}

type policyRuleV1 struct {
	RuleID       string           `json:"rule_id"`
	Operator     string           `json:"operator"`
	Selector     *selectorV1      `json:"selector,omitempty"`
	Expected     json.RawMessage  `json:"expected,omitempty"`
	Minimum      *string          `json:"minimum,omitempty"`
	Maximum      *string          `json:"maximum,omitempty"`
	Tolerance    *string          `json:"tolerance,omitempty"`
	EvidenceType *evidence.Type   `json:"evidence_type,omitempty"`
	SourceID     *string          `json:"source_id,omitempty"`
	MinimumCount *uint32          `json:"minimum_count,omitempty"`
	Steps        []sequenceStepV1 `json:"steps,omitempty"`
	MaxGap       *string          `json:"max_gap,omitempty"`
	MaxDuration  *string          `json:"max_duration,omitempty"`
}

type selectorV1 struct {
	EvidenceType evidence.Type `json:"evidence_type"`
	SourceID     string        `json:"source_id,omitempty"`
	JSONPointer  string        `json:"json_pointer,omitempty"`
}

type sequenceStepV1 struct {
	Selector selectorV1      `json:"selector"`
	Expected json.RawMessage `json:"expected"`
}

func (compiler PolicyDocumentCompiler) ValidatePolicyDocument(
	ctx context.Context,
	version *policy.Version,
) error {
	if version == nil {
		return ErrInvalidPolicyDocument
	}
	if _, err := compiler.CompileQualificationPolicy(ctx, version); err != nil {
		return err
	}
	for _, ruleID := range version.Snapshot().RequiredRuleIDs {
		if _, err := compiler.CompileRule(ctx, version, ruleID); err != nil {
			return err
		}
	}
	return nil
}

func (PolicyDocumentCompiler) CompileQualificationPolicy(
	_ context.Context,
	version *policy.Version,
) (evidence.QualificationPolicy, error) {
	document, err := decodePolicyDocument(version)
	if err != nil || document.EvidenceQualification == nil {
		return evidence.QualificationPolicy{}, ErrInvalidPolicyDocument
	}
	input := document.EvidenceQualification
	maxAge, err := duration(input.MaxAge)
	if err != nil {
		return evidence.QualificationPolicy{}, err
	}
	futureTolerance, err := duration(input.FutureTolerance)
	if err != nil {
		return evidence.QualificationPolicy{}, err
	}
	trustedSources, err := stringSet(input.TrustedSources)
	if err != nil {
		return evidence.QualificationPolicy{}, err
	}
	acquisitionMethods, err := stringSet(input.AllowedAcquisitionMethods)
	if err != nil {
		return evidence.QualificationPolicy{}, err
	}
	requiredProvenance, err := stringList(input.RequiredProvenance)
	if err != nil {
		return evidence.QualificationPolicy{}, err
	}
	requiredPayloadFields, err := stringList(input.RequiredPayloadFields)
	if err != nil {
		return evidence.QualificationPolicy{}, err
	}
	allowedTypes := make(map[evidence.Type]bool, len(input.AllowedTypes))
	for _, evidenceType := range input.AllowedTypes {
		evidenceType = evidence.Type(strings.TrimSpace(string(evidenceType)))
		if evidenceType == "" || allowedTypes[evidenceType] {
			return evidence.QualificationPolicy{}, ErrInvalidPolicyDocument
		}
		allowedTypes[evidenceType] = true
	}
	compiled := evidence.QualificationPolicy{
		Version:        strings.TrimSpace(input.Version),
		TrustedSources: trustedSources, AllowedTypes: allowedTypes,
		AllowedAcquisitionMethods: acquisitionMethods,
		MaxAge:                    maxAge, FutureTolerance: futureTolerance,
		RequireConfidence:     input.RequireConfidence,
		MinimumConfidence:     input.MinimumConfidence,
		RequiredProvenance:    requiredProvenance,
		RequiredPayloadFields: requiredPayloadFields,
	}
	if _, err = evidence.NewQualifier(compiled); err != nil {
		return evidence.QualificationPolicy{}, fmt.Errorf("%w: %v", ErrInvalidPolicyDocument, err)
	}
	return compiled, nil
}

func (PolicyDocumentCompiler) CompileRule(
	_ context.Context,
	version *policy.Version,
	ruleID string,
) (pds.RuleOperator, error) {
	document, err := decodePolicyDocument(version)
	if err != nil {
		return nil, err
	}
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return nil, ErrRuleIDRequired
	}
	if len(document.Rules) == 0 {
		return nil, ErrInvalidPolicyDocument
	}
	var selected *policyRuleV1
	seen := make(map[string]struct{}, len(document.Rules))
	for index := range document.Rules {
		id := strings.TrimSpace(document.Rules[index].RuleID)
		if id == "" {
			return nil, ErrInvalidPolicyDocument
		}
		if _, exists := seen[id]; exists {
			return nil, fmt.Errorf("%w: %s", ErrDuplicatePolicyRule, id)
		}
		seen[id] = struct{}{}
		if id == ruleID {
			selected = &document.Rules[index]
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("%w: %s", ErrPolicyRuleNotFound, ruleID)
	}
	return compilePolicyRule(*selected)
}

func decodePolicyDocument(version *policy.Version) (policyDocumentV1, error) {
	if version == nil {
		return policyDocumentV1{}, ErrInvalidPolicyDocument
	}
	snapshot := version.Snapshot()
	if snapshot.SchemaVersion != PolicyDocumentSchemaV1 {
		return policyDocumentV1{}, fmt.Errorf("%w: %s", ErrUnsupportedPolicySchema, snapshot.SchemaVersion)
	}
	var document policyDocumentV1
	if err := decodeStrict(snapshot.Document, &document); err != nil {
		return policyDocumentV1{}, ErrInvalidPolicyDocument
	}
	return document, nil
}

func compilePolicyRule(rule policyRuleV1) (pds.RuleOperator, error) {
	rule.RuleID = strings.TrimSpace(rule.RuleID)
	switch strings.ToUpper(strings.TrimSpace(rule.Operator)) {
	case "MATCH":
		if rule.Selector == nil || len(rule.Expected) == 0 || hasNumericFields(rule) ||
			rule.EvidenceType != nil || rule.SourceID != nil || len(rule.Steps) != 0 ||
			rule.MaxGap != nil || rule.MaxDuration != nil {
			return nil, ErrInvalidPolicyDocument
		}
		return NewMatchOperator(rule.RuleID, selector(*rule.Selector), rule.Expected)
	case "RANGE":
		if rule.Selector == nil || rule.Minimum == nil || rule.Maximum == nil ||
			len(rule.Expected) != 0 || rule.Tolerance != nil || rule.EvidenceType != nil ||
			rule.SourceID != nil || rule.MinimumCount != nil || len(rule.Steps) != 0 ||
			rule.MaxGap != nil || rule.MaxDuration != nil {
			return nil, ErrInvalidPolicyDocument
		}
		return NewRangeOperator(rule.RuleID, selector(*rule.Selector), *rule.Minimum, *rule.Maximum)
	case "TOLERANCE":
		if rule.Selector == nil || len(rule.Expected) == 0 || rule.Tolerance == nil ||
			rule.Minimum != nil || rule.Maximum != nil || rule.EvidenceType != nil ||
			rule.SourceID != nil || rule.MinimumCount != nil || len(rule.Steps) != 0 ||
			rule.MaxGap != nil || rule.MaxDuration != nil {
			return nil, ErrInvalidPolicyDocument
		}
		var expected json.Number
		if err := json.Unmarshal(rule.Expected, &expected); err != nil {
			return nil, ErrInvalidPolicyDocument
		}
		return NewToleranceOperator(rule.RuleID, selector(*rule.Selector), expected.String(), *rule.Tolerance)
	case "EXISTENCE":
		if rule.EvidenceType == nil || rule.MinimumCount == nil || rule.Selector != nil ||
			len(rule.Expected) != 0 || hasNumericFieldsExceptMinimumCount(rule) || len(rule.Steps) != 0 ||
			rule.MaxGap != nil || rule.MaxDuration != nil {
			return nil, ErrInvalidPolicyDocument
		}
		sourceID := ""
		if rule.SourceID != nil {
			sourceID = *rule.SourceID
		}
		return NewExistenceOperator(rule.RuleID, *rule.EvidenceType, sourceID, *rule.MinimumCount)
	case "SEQUENCE":
		if len(rule.Steps) < 2 || rule.Selector != nil || len(rule.Expected) != 0 ||
			hasNumericFields(rule) || rule.EvidenceType != nil || rule.SourceID != nil {
			return nil, ErrInvalidPolicyDocument
		}
		steps := make([]SequenceStep, len(rule.Steps))
		for index, step := range rule.Steps {
			if len(step.Expected) == 0 {
				return nil, ErrInvalidPolicyDocument
			}
			steps[index] = SequenceStep{Selector: selector(step.Selector), Expected: step.Expected}
		}
		maxGap, err := duration(rule.MaxGap)
		if err != nil {
			return nil, err
		}
		maxDuration, err := duration(rule.MaxDuration)
		if err != nil {
			return nil, err
		}
		return NewSequenceOperator(rule.RuleID, steps, maxGap, maxDuration)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedOperator, rule.Operator)
	}
}

func selector(value selectorV1) Selector {
	return Selector{EvidenceType: value.EvidenceType, SourceID: value.SourceID, JSONPointer: value.JSONPointer}
}

func hasNumericFields(rule policyRuleV1) bool {
	return rule.Minimum != nil || rule.Maximum != nil || rule.Tolerance != nil || rule.MinimumCount != nil
}

func hasNumericFieldsExceptMinimumCount(rule policyRuleV1) bool {
	return rule.Minimum != nil || rule.Maximum != nil || rule.Tolerance != nil
}

func duration(value *string) (time.Duration, error) {
	if value == nil || strings.TrimSpace(*value) == "" {
		return 0, nil
	}
	result, err := time.ParseDuration(*value)
	if err != nil || result < 0 {
		return 0, ErrInvalidPolicyDocument
	}
	return result, nil
}

func stringSet(values []string) (map[string]bool, error) {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || result[value] {
			return nil, ErrInvalidPolicyDocument
		}
		result[value] = true
	}
	return result, nil
}

func stringList(values []string) ([]string, error) {
	set, err := stringSet(values)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if set[value] {
			result = append(result, value)
			delete(set, value)
		}
	}
	return result, nil
}

func decodeStrict(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ErrInvalidPolicyDocument
	}
	return nil
}

var _ pds.PolicyRuleCompiler = PolicyDocumentCompiler{}
var _ pds.PolicyQualificationCompiler = PolicyDocumentCompiler{}
var _ policy.DocumentValidator = PolicyDocumentCompiler{}
