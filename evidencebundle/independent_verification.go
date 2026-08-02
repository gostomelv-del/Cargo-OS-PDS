package evidencebundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"cargoos/evaluation"
	"cargoos/evidence"
	"cargoos/pds"
	"cargoos/policy"
	"cargoos/ruleoperator"
)

var (
	ErrDecisionTraceRequired         = errors.New("evidencebundle: decision trace is required")
	ErrIndependentVerificationScope  = errors.New("evidencebundle: decision is outside independent verification scope")
	ErrIndependentVerificationFailed = errors.New("evidencebundle: independent decision verification failed")
	ErrRecalculatedOutcomeMismatch   = errors.New("evidencebundle: recalculated Rule Outcome mismatch")
	ErrRecalculatedDecisionMismatch  = errors.New("evidencebundle: recalculated decision mismatch")
)

type RecalculatedOutcome struct {
	RuleID      string                       `json:"rule_id"`
	Status      evaluation.RuleOutcomeStatus `json:"status"`
	ReasonCodes []evaluation.ReasonCode      `json:"reason_codes,omitempty"`
}

type IndependentVerificationReport struct {
	BundleID           uuid.UUID                     `json:"bundle_id"`
	EvaluationID       uuid.UUID                     `json:"evaluation_id"`
	Policy             PolicyReference               `json:"policy"`
	StoredResult       evaluation.VerificationResult `json:"stored_result"`
	RecalculatedResult evaluation.VerificationResult `json:"recalculated_result"`
	Outcomes           []RecalculatedOutcome         `json:"outcomes"`
	Verified           bool                          `json:"verified"`
}

// VerifyDecision independently recompiles the exact embedded Policy, executes
// every required Rule Operator over the exact embedded Evidence Set, and
// compares the recalculated outcomes and final result with the Decision Trace.
func VerifyDecision(ctx context.Context, bundle Bundle) (IndependentVerificationReport, error) {
	if err := Verify(bundle); err != nil {
		return IndependentVerificationReport{}, err
	}
	snapshot, err := PolicySnapshot(bundle)
	if err != nil {
		return IndependentVerificationReport{}, err
	}
	trace, evidenceSnapshots, err := verificationInputs(bundle)
	if err != nil {
		return IndependentVerificationReport{}, err
	}
	if trace.State != evaluation.StateCompleted || trace.CompletedAt == nil ||
		len(trace.RequiredRuleIDs) == 0 || len(trace.MissingRuleIDs) != 0 ||
		len(trace.RuleOutcomes) != len(trace.RequiredRuleIDs) {
		return IndependentVerificationReport{}, ErrIndependentVerificationScope
	}
	if trace.EvaluationID != bundle.Manifest.EvaluationID || trace.SessionID != bundle.Manifest.SessionID ||
		trace.PolicyBinding == nil || trace.PolicyBinding.PolicyID != snapshot.PolicyID ||
		trace.PolicyBinding.Version != snapshot.Version || trace.PolicyBinding.Hash != snapshot.Hash {
		return IndependentVerificationReport{}, ErrIndependentVerificationFailed
	}
	if !sameStrings(trace.RequiredRuleIDs, snapshot.RequiredRuleIDs) {
		return IndependentVerificationReport{}, ErrIndependentVerificationFailed
	}
	version, err := policy.Rehydrate(snapshot)
	if err != nil {
		return IndependentVerificationReport{}, err
	}
	compiler := ruleoperator.PolicyDocumentCompiler{}
	if err = compiler.ValidatePolicyDocument(ctx, version); err != nil {
		return IndependentVerificationReport{}, err
	}

	stored := make(map[string]evaluation.RuleOutcome, len(trace.RuleOutcomes))
	for _, outcome := range trace.RuleOutcomes {
		if _, duplicate := stored[outcome.RuleID]; duplicate {
			return IndependentVerificationReport{}, ErrIndependentVerificationFailed
		}
		stored[outcome.RuleID] = outcome
	}
	recalculated := make([]RecalculatedOutcome, 0, len(trace.RequiredRuleIDs))
	for _, ruleID := range trace.RequiredRuleIDs {
		operator, compileErr := compiler.CompileRule(ctx, version, ruleID)
		if compileErr != nil {
			return IndependentVerificationReport{}, compileErr
		}
		decision, executeErr := operator.Evaluate(ctx, pds.RuleInput{
			EvaluationID: trace.EvaluationID, SessionID: trace.SessionID,
			PolicyID: snapshot.PolicyID, PolicyVersion: snapshot.Version,
			PolicyHash: snapshot.Hash, Evidence: copyEvidenceForVerification(evidenceSnapshots),
		})
		if executeErr != nil {
			return IndependentVerificationReport{}, fmt.Errorf("%w: %s: %v", ErrIndependentVerificationFailed, ruleID, executeErr)
		}
		outcome := RecalculatedOutcome{RuleID: ruleID, Status: decision.Status, ReasonCodes: append([]evaluation.ReasonCode(nil), decision.ReasonCodes...)}
		recalculated = append(recalculated, outcome)
		expected, exists := stored[ruleID]
		if !exists || expected.Status != outcome.Status || !sameReasonCodes(expected.ReasonCodes, outcome.ReasonCodes) {
			return IndependentVerificationReport{}, fmt.Errorf("%w: %s", ErrRecalculatedOutcomeMismatch, ruleID)
		}
	}
	result := deriveVerificationResult(recalculated)
	if result != trace.Result {
		return IndependentVerificationReport{}, fmt.Errorf("%w: stored=%s recalculated=%s", ErrRecalculatedDecisionMismatch, trace.Result, result)
	}
	return IndependentVerificationReport{
		BundleID: bundle.Manifest.BundleID, EvaluationID: trace.EvaluationID,
		Policy: bundle.Manifest.Policy, StoredResult: trace.Result,
		RecalculatedResult: result, Outcomes: recalculated, Verified: true,
	}, nil
}

func verificationInputs(bundle Bundle) (evaluation.DecisionTrace, []evidence.Snapshot, error) {
	var trace evaluation.DecisionTrace
	var traceFound bool
	evidenceSnapshots := make([]evidence.Snapshot, 0)
	for _, object := range bundle.Objects {
		switch {
		case object.Path == "decision-trace.json":
			if traceFound || json.Unmarshal(object.Payload, &trace) != nil {
				return evaluation.DecisionTrace{}, nil, ErrDecisionTraceRequired
			}
			traceFound = true
		case strings.HasPrefix(object.Path, "evidence/"):
			var snapshot evidence.Snapshot
			if json.Unmarshal(object.Payload, &snapshot) != nil {
				return evaluation.DecisionTrace{}, nil, ErrEvidenceObjectMismatch
			}
			rehydrated, err := evidence.Rehydrate(snapshot)
			if err != nil {
				return evaluation.DecisionTrace{}, nil, err
			}
			evidenceSnapshots = append(evidenceSnapshots, rehydrated.Snapshot())
		}
	}
	if !traceFound || trace.EvidenceBinding == nil || len(evidenceSnapshots) != len(trace.EvidenceBinding.Evidence) {
		return evaluation.DecisionTrace{}, nil, ErrDecisionTraceRequired
	}
	byID := make(map[uuid.UUID]evidence.Snapshot, len(evidenceSnapshots))
	for _, snapshot := range evidenceSnapshots {
		if snapshot.SessionID != trace.SessionID {
			return evaluation.DecisionTrace{}, nil, ErrEvidenceObjectMismatch
		}
		if _, duplicate := byID[snapshot.EvidenceID]; duplicate {
			return evaluation.DecisionTrace{}, nil, ErrEvidenceObjectMismatch
		}
		byID[snapshot.EvidenceID] = snapshot
	}
	ordered := make([]evidence.Snapshot, 0, len(trace.EvidenceBinding.Evidence))
	for _, reference := range trace.EvidenceBinding.Evidence {
		if reference.Status != evaluation.EvidenceQualified {
			return evaluation.DecisionTrace{}, nil, ErrIndependentVerificationScope
		}
		snapshot, exists := byID[reference.EvidenceID]
		if !exists {
			return evaluation.DecisionTrace{}, nil, ErrEvidenceObjectMismatch
		}
		ordered = append(ordered, snapshot)
		delete(byID, reference.EvidenceID)
	}
	if len(byID) != 0 {
		return evaluation.DecisionTrace{}, nil, ErrEvidenceObjectMismatch
	}
	return trace, ordered, nil
}

func copyEvidenceForVerification(source []evidence.Snapshot) []evidence.Snapshot {
	result := make([]evidence.Snapshot, len(source))
	for index, snapshot := range source {
		object, _ := evidence.Rehydrate(snapshot)
		result[index] = object.Snapshot()
	}
	return result
}

func deriveVerificationResult(outcomes []RecalculatedOutcome) evaluation.VerificationResult {
	result := evaluation.ResultVerified
	for _, outcome := range outcomes {
		switch outcome.Status {
		case evaluation.RuleOutcomeFail:
			result = evaluation.ResultRejected
		case evaluation.RuleOutcomeInconclusive:
			if result != evaluation.ResultRejected {
				result = evaluation.ResultManualReview
			}
		case evaluation.RuleOutcomeWarning:
			if result == evaluation.ResultVerified {
				result = evaluation.ResultVerifiedWithException
			}
		}
	}
	return result
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameReasonCodes(left, right []evaluation.ReasonCode) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
