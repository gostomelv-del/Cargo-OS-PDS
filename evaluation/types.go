package evaluation

import (
	"errors"
	"regexp"
	"strings"
)

var (
	ErrInvalidStateTransition     = errors.New("evaluation: invalid state transition")
	ErrReasonCodeRequired         = errors.New("evaluation: reason code required")
	ErrCancellationReasonRequired = errors.New("evaluation: cancellation reason required")
	ErrInvalidExpirationTime      = errors.New("evaluation: invalid expiration time")
	ErrEvaluationIDRequired       = errors.New("evaluation: evaluation ID required")
	ErrSessionIDRequired          = errors.New("evaluation: session ID required")
	ErrInvalidEvaluationSnapshot  = errors.New("evaluation: invalid snapshot")
	ErrInvalidStartTime           = errors.New("evaluation: invalid start time")
	ErrInvalidCompletionTime      = errors.New("evaluation: invalid completion time")
	ErrInvalidCompletionResult    = errors.New("evaluation: invalid completion result")
	ErrRuleIDRequired             = errors.New("evaluation: rule ID required")
	ErrRuleOutcomeAlreadyRecorded = errors.New("evaluation: rule outcome already recorded")
	ErrInvalidRuleOutcome         = errors.New("evaluation: invalid rule outcome")
)

type EvaluationState string

const (
	StateCreated   EvaluationState = "CREATED"
	StateRunning   EvaluationState = "RUNNING"
	StateCompleted EvaluationState = "COMPLETED"
	StateCancelled EvaluationState = "CANCELLED"
	StateExpired   EvaluationState = "EXPIRED"
)

func (s EvaluationState) CanTransitionTo(target EvaluationState) bool {
	switch s {
	case StateCreated:
		return target == StateRunning || target == StateCancelled || target == StateExpired
	case StateRunning:
		return target == StateCompleted || target == StateCancelled || target == StateExpired
	default:
		return false
	}
}
func (s EvaluationState) IsTerminal() bool {
	return s == StateCompleted || s == StateCancelled || s == StateExpired
}

type VerificationResult string

const (
	ResultUnknown               VerificationResult = "UNKNOWN"
	ResultVerified              VerificationResult = "VERIFIED"
	ResultVerifiedWithException VerificationResult = "VERIFIED_WITH_EXCEPTION"
	ResultRejected              VerificationResult = "REJECTED"
	ResultManualReview          VerificationResult = "MANUAL_REVIEW"
	ResultSystemException       VerificationResult = "SYSTEM_EXCEPTION"
)

func (r VerificationResult) IsValid() bool {
	switch r {
	case ResultUnknown, ResultVerified, ResultVerifiedWithException, ResultRejected, ResultManualReview, ResultSystemException:
		return true
	default:
		return false
	}
}

var reasonCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)

type ReasonCode string

func NewReasonCode(value string) (ReasonCode, error) {
	v := strings.ToUpper(strings.TrimSpace(value))
	if !reasonCodePattern.MatchString(v) {
		return "", errors.New("evaluation: invalid reason code")
	}
	return ReasonCode(v), nil
}
func (r ReasonCode) String() string { return string(r) }

type RuleOutcomeStatus string

const (
	RuleOutcomePass         RuleOutcomeStatus = "PASS"
	RuleOutcomeWarning      RuleOutcomeStatus = "WARNING"
	RuleOutcomeFail         RuleOutcomeStatus = "FAIL"
	RuleOutcomeInconclusive RuleOutcomeStatus = "INCONCLUSIVE"
)

func (s RuleOutcomeStatus) IsValid() bool {
	return s == RuleOutcomePass || s == RuleOutcomeWarning || s == RuleOutcomeFail || s == RuleOutcomeInconclusive
}
