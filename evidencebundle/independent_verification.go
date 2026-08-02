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

	recalculated := make([]RecalculatedOutcome, 0, len(trace.RequiredRuleIDs))
	result := evaluation.ResultVerified
	for index, ruleID := range trace.RequiredRuleIDs {
		expected := trace.RuleOutcomes[index]
		if expected.RuleID != ruleID {
			return IndependentVerificationReport{}, ErrIndependentVerificationFailed
		}
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
		if expected.Status != outcome.Status || !sameReasonCodes(expected.ReasonCodes, outcome.ReasonCodes) {
			return IndependentVerificationReport{}, fmt.Errorf("%w: %s", ErrRecalculatedOutcomeMismatch, ruleID)
		}
		result = updateVerificationResult(result, outcome.Status)
	}
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
	byID := make(map[uuid.UUID]evidence.Snapshot, len(bundle.Objects))
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
			snapshot = rehydrated.Snapshot()
			if _, duplicate := byID[snapshot.EvidenceID]; duplicate {
				return evaluation.DecisionTrace{}, nil, ErrEvidenceObjectMismatch
			}
			byID[snapshot.EvidenceID] = snapshot
		}
	}
	if !traceFound || trace.EvidenceBinding == nil || len(byID) != len(trace.EvidenceBinding.Evidence) {
		return evaluation.DecisionTrace{}, nil, ErrDecisionTraceRequired
	}
	ordered := make([]evidence.Snapshot, len(trace.EvidenceBinding.Evidence))
	for index, reference := range trace.EvidenceBinding.Evidence {
		if reference.Status != evaluation.EvidenceQualified {
			return evaluation.DecisionTrace{}, nil, ErrIndependentVerificationScope
		}
		snapshot, exists := byID[reference.EvidenceID]
		if !exists {
			return evaluation.DecisionTrace{}, nil, ErrEvidenceObjectMismatch
		}
		if snapshot.SessionID != trace.SessionID {
			return evaluation.DecisionTrace{}, nil, ErrEvidenceObjectMismatch
		}
		ordered[index] = snapshot
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
		result[index] = snapshot
		result[index].Payload = append(json.RawMessage(nil), snapshot.Payload...)
		if snapshot.Confidence != nil {
			confidence := *snapshot.Confidence
			result[index].Confidence = &confidence
		}
		if snapshot.Provenance != nil {
			result[index].Provenance = make(map[string]string, len(snapshot.Provenance))
			for key, value := range snapshot.Provenance {
				result[index].Provenance[key] = value
			}
		}
	}
	return result
}

func updateVerificationResult(result evaluation.VerificationResult, status evaluation.RuleOutcomeStatus) evaluation.VerificationResult {
	switch status {
	case evaluation.RuleOutcomeFail:
		return evaluation.ResultRejected
	case evaluation.RuleOutcomeInconclusive:
		if result != evaluation.ResultRejected {
			return evaluation.ResultManualReview
		}
	case evaluation.RuleOutcomeWarning:
		if result == evaluation.ResultVerified {
			return evaluation.ResultVerifiedWithException
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
