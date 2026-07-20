package evaluation

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrRuleOutcomeConflict            = errors.New("evaluation: conflicting rule outcome already recorded")
	ErrInvalidRuleOutcomeTimestamp    = errors.New("evaluation: invalid rule outcome timestamp")
	ErrRuleOutcomeTimestampRequired   = errors.New("evaluation: rule outcome timestamp is required")
	ErrUnknownRule                    = errors.New("evaluation: unknown rule")
	ErrRuleOutcomeNotFound            = errors.New("evaluation: rule outcome not found")
	ErrStaleRuleOutcomeReplacement    = errors.New("evaluation: replacement outcome is older than current outcome")
	ErrRuleOutcomeRemovalTimeRequired = errors.New("evaluation: rule outcome removal time is required")
	ErrRuleOutcomeResetTimeRequired   = errors.New("evaluation: rule outcome reset time is required")
	ErrEvaluationVersionConflict      = errors.New("evaluation: aggregate version conflict")
)

type RuleOutcomeBatchRecordedEvent struct {
	EvaluationID uuid.UUID
	SessionID    uuid.UUID
	Outcomes     []RuleOutcome
	RecordedAt   time.Time
	Version      uint64
}

type RuleOutcomeReplacedEvent struct {
	EvaluationID uuid.UUID
	SessionID    uuid.UUID
	Previous     RuleOutcome
	Replacement  RuleOutcome
	ReplacedAt   time.Time
	Version      uint64
}

type RuleOutcomeBatchReplacedEvent struct {
	EvaluationID uuid.UUID
	SessionID    uuid.UUID
	Previous     []RuleOutcome
	Replacements []RuleOutcome
	ReplacedAt   time.Time
	Version      uint64
}

type RuleOutcomeRemovedEvent struct {
	EvaluationID uuid.UUID
	SessionID    uuid.UUID
	Outcome      RuleOutcome
	RemovedAt    time.Time
	Version      uint64
}

type RuleOutcomeBatchRemovedEvent struct {
	EvaluationID uuid.UUID
	SessionID    uuid.UUID
	Outcomes     []RuleOutcome
	RemovedAt    time.Time
	Version      uint64
}

type RuleOutcomesResetEvent struct {
	EvaluationID uuid.UUID
	SessionID    uuid.UUID
	Outcomes     []RuleOutcome
	ResetAt      time.Time
	Version      uint64
}

type RuleOutcomeReplacement struct {
	Replacement RuleOutcome
	ReplacedAt  time.Time
}

func normalizeRuleOutcome(o RuleOutcome) (RuleOutcome, error) {
	o.RuleID = strings.TrimSpace(o.RuleID)
	if o.RuleID == "" {
		return RuleOutcome{}, ErrRuleIDRequired
	}
	if !o.Status.IsValid() || o.EvaluatedAt.IsZero() {
		return RuleOutcome{}, ErrInvalidRuleOutcome
	}
	reasons, err := normalizeReasonCodes(o.ReasonCodes)
	if err != nil {
		return RuleOutcome{}, err
	}
	if o.Status == RuleOutcomePass && len(reasons) != 0 {
		return RuleOutcome{}, ErrInvalidRuleOutcome
	}
	if o.Status != RuleOutcomePass && len(reasons) == 0 {
		return RuleOutcome{}, ErrInvalidRuleOutcome
	}
	o.ReasonCodes = reasons
	o.EvaluatedAt = o.EvaluatedAt.UTC()
	return o, nil
}

func copyRuleOutcome(o RuleOutcome) RuleOutcome {
	o.ReasonCodes = copyReasonCodes(o.ReasonCodes)
	return o
}

func copyRuleOutcomes(source []RuleOutcome) []RuleOutcome {
	if len(source) == 0 {
		return nil
	}
	target := make([]RuleOutcome, len(source))
	for i, outcome := range source {
		target[i] = copyRuleOutcome(outcome)
	}
	return target
}

func ruleOutcomesEqual(left, right RuleOutcome) bool {
	if left.RuleID != right.RuleID || left.Status != right.Status || !left.EvaluatedAt.Equal(right.EvaluatedAt) {
		return false
	}
	if len(left.ReasonCodes) != len(right.ReasonCodes) {
		return false
	}
	for i := range left.ReasonCodes {
		if left.ReasonCodes[i] != right.ReasonCodes[i] {
			return false
		}
	}
	return true
}

func (e *EvaluationAggregate) IsRuleRequired(ruleID string) bool {
	ruleID = strings.TrimSpace(ruleID)
	for _, id := range e.requiredRuleIDs {
		if id == ruleID {
			return true
		}
	}
	return false
}

func (e *EvaluationAggregate) RuleOutcomeByID(ruleID string) (RuleOutcome, bool) {
	idx := e.ruleOutcomeIndex(strings.TrimSpace(ruleID))
	if idx < 0 {
		return RuleOutcome{}, false
	}
	return copyRuleOutcome(e.ruleOutcomes[idx]), true
}

func (e *EvaluationAggregate) HasRecordedRule(ruleID string) bool {
	return e.ruleOutcomeIndex(strings.TrimSpace(ruleID)) >= 0
}

func (e *EvaluationAggregate) ruleOutcomeIndex(ruleID string) int {
	for i := range e.ruleOutcomes {
		if e.ruleOutcomes[i].RuleID == ruleID {
			return i
		}
	}
	return -1
}

func (e *EvaluationAggregate) validateRuleOutcomeBatch(outcomes []RuleOutcome) ([]RuleOutcome, error) {
	normalized := make([]RuleOutcome, 0, len(outcomes))
	batchByRuleID := make(map[string]RuleOutcome, len(outcomes))
	for _, outcome := range outcomes {
		value, err := normalizeRuleOutcome(outcome)
		if err != nil {
			return nil, err
		}
		if e.startedAt == nil || value.EvaluatedAt.Before(*e.startedAt) {
			return nil, fmt.Errorf("%w: %s", ErrInvalidRuleOutcomeTimestamp, value.RuleID)
		}
		if len(e.requiredRuleIDs) > 0 && !e.IsRuleRequired(value.RuleID) {
			return nil, fmt.Errorf("%w: %s", ErrUnknownRule, value.RuleID)
		}
		if previous, exists := batchByRuleID[value.RuleID]; exists {
			if ruleOutcomesEqual(previous, value) {
				continue
			}
			return nil, fmt.Errorf("%w: %s", ErrRuleOutcomeConflict, value.RuleID)
		}
		if existing, found := e.RuleOutcomeByID(value.RuleID); found && !ruleOutcomesEqual(existing, value) {
			return nil, fmt.Errorf("%w: %s", ErrRuleOutcomeConflict, value.RuleID)
		}
		batchByRuleID[value.RuleID] = copyRuleOutcome(value)
		normalized = append(normalized, copyRuleOutcome(value))
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].RuleID < normalized[j].RuleID })
	return normalized, nil
}

func (e *EvaluationAggregate) RecordRuleOutcomesAtomic(outcomes []RuleOutcome) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	if e.state != StateRunning {
		return ErrInvalidStateTransition
	}
	normalized, err := e.validateRuleOutcomeBatch(outcomes)
	if err != nil {
		return err
	}
	for _, outcome := range normalized {
		if existing, found := e.RuleOutcomeByID(outcome.RuleID); found && ruleOutcomesEqual(existing, outcome) {
			continue
		}
		e.ruleOutcomes = append(e.ruleOutcomes, copyRuleOutcome(outcome))
		e.version++
		e.addDomainEvent(RuleOutcomeRecordedEvent{RuleID: outcome.RuleID, Status: outcome.Status, ReasonCodes: copyReasonCodes(outcome.ReasonCodes), EvaluatedAt: outcome.EvaluatedAt, Version: e.version})
	}
	return nil
}

func (e *EvaluationAggregate) RecordRuleOutcomeBatch(outcomes []RuleOutcome, recordedAt time.Time) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	if e.state != StateRunning {
		return ErrInvalidStateTransition
	}
	if len(outcomes) == 0 {
		return nil
	}
	if recordedAt.IsZero() {
		return ErrRuleOutcomeTimestampRequired
	}
	recordedAt = recordedAt.UTC()
	if e.startedAt == nil || recordedAt.Before(*e.startedAt) {
		return ErrInvalidRuleOutcomeTimestamp
	}
	normalized, err := e.validateRuleOutcomeBatch(outcomes)
	if err != nil {
		return err
	}
	pending := make([]RuleOutcome, 0, len(normalized))
	for _, outcome := range normalized {
		if existing, found := e.RuleOutcomeByID(outcome.RuleID); found && ruleOutcomesEqual(existing, outcome) {
			continue
		}
		pending = append(pending, copyRuleOutcome(outcome))
	}
	if len(pending) == 0 {
		return nil
	}
	e.ruleOutcomes = append(e.ruleOutcomes, copyRuleOutcomes(pending)...)
	e.version++
	e.addDomainEvent(RuleOutcomeBatchRecordedEvent{e.id, e.sessionID, copyRuleOutcomes(pending), recordedAt, e.version})
	return nil
}

func (e *EvaluationAggregate) RecordRuleOutcomeBatchNow(outcomes []RuleOutcome) error {
	return e.RecordRuleOutcomeBatch(outcomes, time.Now().UTC())
}

func (e *EvaluationAggregate) ReplaceRuleOutcome(replacement RuleOutcome, replacedAt time.Time) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	if e.state != StateRunning {
		return ErrInvalidStateTransition
	}
	if replacedAt.IsZero() {
		return ErrRuleOutcomeTimestampRequired
	}
	replacedAt = replacedAt.UTC()
	normalized, err := normalizeRuleOutcome(replacement)
	if err != nil {
		return err
	}
	if e.startedAt == nil || replacedAt.Before(*e.startedAt) || normalized.EvaluatedAt.Before(*e.startedAt) || normalized.EvaluatedAt.After(replacedAt) {
		return ErrInvalidRuleOutcomeTimestamp
	}
	if len(e.requiredRuleIDs) > 0 && !e.IsRuleRequired(normalized.RuleID) {
		return fmt.Errorf("%w: %s", ErrUnknownRule, normalized.RuleID)
	}
	index := e.ruleOutcomeIndex(normalized.RuleID)
	if index < 0 {
		return fmt.Errorf("%w: %s", ErrRuleOutcomeNotFound, normalized.RuleID)
	}
	previous := e.ruleOutcomes[index]
	if ruleOutcomesEqual(previous, normalized) {
		return nil
	}
	if normalized.EvaluatedAt.Before(previous.EvaluatedAt) {
		return fmt.Errorf("%w: %s", ErrStaleRuleOutcomeReplacement, normalized.RuleID)
	}
	e.ruleOutcomes[index] = copyRuleOutcome(normalized)
	e.version++
	e.addDomainEvent(RuleOutcomeReplacedEvent{e.id, e.sessionID, copyRuleOutcome(previous), copyRuleOutcome(normalized), replacedAt, e.version})
	return nil
}

func (e *EvaluationAggregate) ReplaceRuleOutcomeNow(replacement RuleOutcome) error {
	return e.ReplaceRuleOutcome(replacement, time.Now().UTC())
}

func (e *EvaluationAggregate) ReplaceRuleOutcomesAtomic(replacements []RuleOutcomeReplacement, replacedAt time.Time) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	if e.state != StateRunning {
		return ErrInvalidStateTransition
	}
	if len(replacements) == 0 {
		return nil
	}
	if replacedAt.IsZero() {
		return ErrRuleOutcomeTimestampRequired
	}
	replacedAt = replacedAt.UTC()
	if e.startedAt == nil || replacedAt.Before(*e.startedAt) {
		return ErrInvalidRuleOutcomeTimestamp
	}
	byID := make(map[string]RuleOutcome, len(replacements))
	ids := make([]string, 0, len(replacements))
	for _, item := range replacements {
		at := item.ReplacedAt
		if at.IsZero() {
			at = replacedAt
		}
		if at.UTC().After(replacedAt) {
			return ErrInvalidRuleOutcomeTimestamp
		}
		value, err := normalizeRuleOutcome(item.Replacement)
		if err != nil {
			return err
		}
		if value.EvaluatedAt.After(replacedAt) || value.EvaluatedAt.Before(*e.startedAt) {
			return ErrInvalidRuleOutcomeTimestamp
		}
		if len(e.requiredRuleIDs) > 0 && !e.IsRuleRequired(value.RuleID) {
			return fmt.Errorf("%w: %s", ErrUnknownRule, value.RuleID)
		}
		idx := e.ruleOutcomeIndex(value.RuleID)
		if idx < 0 {
			return fmt.Errorf("%w: %s", ErrRuleOutcomeNotFound, value.RuleID)
		}
		if value.EvaluatedAt.Before(e.ruleOutcomes[idx].EvaluatedAt) {
			return fmt.Errorf("%w: %s", ErrStaleRuleOutcomeReplacement, value.RuleID)
		}
		if old, exists := byID[value.RuleID]; exists && !ruleOutcomesEqual(old, value) {
			return fmt.Errorf("%w: %s", ErrRuleOutcomeConflict, value.RuleID)
		}
		if _, exists := byID[value.RuleID]; !exists {
			ids = append(ids, value.RuleID)
		}
		byID[value.RuleID] = value
	}
	sort.Strings(ids)
	previous := make([]RuleOutcome, 0, len(ids))
	pending := make([]RuleOutcome, 0, len(ids))
	for _, id := range ids {
		current := e.ruleOutcomes[e.ruleOutcomeIndex(id)]
		replacement := byID[id]
		if ruleOutcomesEqual(current, replacement) {
			continue
		}
		previous = append(previous, copyRuleOutcome(current))
		pending = append(pending, copyRuleOutcome(replacement))
	}
	if len(pending) == 0 {
		return nil
	}
	for _, replacement := range pending {
		e.ruleOutcomes[e.ruleOutcomeIndex(replacement.RuleID)] = copyRuleOutcome(replacement)
	}
	e.version++
	e.addDomainEvent(RuleOutcomeBatchReplacedEvent{e.id, e.sessionID, copyRuleOutcomes(previous), copyRuleOutcomes(pending), replacedAt, e.version})
	return nil
}

func (e *EvaluationAggregate) RemoveRuleOutcome(ruleID string, removedAt time.Time) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	if e.state != StateRunning {
		return ErrInvalidStateTransition
	}
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return ErrRuleIDRequired
	}
	if removedAt.IsZero() {
		return ErrRuleOutcomeRemovalTimeRequired
	}
	removedAt = removedAt.UTC()
	if e.startedAt == nil || removedAt.Before(*e.startedAt) {
		return ErrInvalidRuleOutcomeTimestamp
	}
	index := e.ruleOutcomeIndex(ruleID)
	if index < 0 {
		return fmt.Errorf("%w: %s", ErrRuleOutcomeNotFound, ruleID)
	}
	outcome := copyRuleOutcome(e.ruleOutcomes[index])
	e.ruleOutcomes = append(e.ruleOutcomes[:index:index], e.ruleOutcomes[index+1:]...)
	e.version++
	e.addDomainEvent(RuleOutcomeRemovedEvent{e.id, e.sessionID, outcome, removedAt, e.version})
	return nil
}

func (e *EvaluationAggregate) RemoveRuleOutcomeNow(ruleID string) error {
	return e.RemoveRuleOutcome(ruleID, time.Now().UTC())
}

func (e *EvaluationAggregate) RemoveRuleOutcomeIfPresent(ruleID string, removedAt time.Time) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return ErrRuleIDRequired
	}
	if !e.HasRecordedRule(ruleID) {
		return nil
	}
	return e.RemoveRuleOutcome(ruleID, removedAt)
}

func normalizeRuleIDsForRemoval(ruleIDs []string) ([]string, error) {
	seen := make(map[string]struct{}, len(ruleIDs))
	out := make([]string, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, ErrRuleIDRequired
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

func (e *EvaluationAggregate) RemoveRuleOutcomesAtomic(ruleIDs []string, removedAt time.Time) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	if e.state != StateRunning {
		return ErrInvalidStateTransition
	}
	if len(ruleIDs) == 0 {
		return nil
	}
	if removedAt.IsZero() {
		return ErrRuleOutcomeRemovalTimeRequired
	}
	removedAt = removedAt.UTC()
	if e.startedAt == nil || removedAt.Before(*e.startedAt) {
		return ErrInvalidRuleOutcomeTimestamp
	}
	ids, err := normalizeRuleIDsForRemoval(ruleIDs)
	if err != nil {
		return err
	}
	removed := make([]RuleOutcome, 0, len(ids))
	removeSet := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		idx := e.ruleOutcomeIndex(id)
		if idx < 0 {
			return fmt.Errorf("%w: %s", ErrRuleOutcomeNotFound, id)
		}
		removed = append(removed, copyRuleOutcome(e.ruleOutcomes[idx]))
		removeSet[id] = struct{}{}
	}
	remaining := make([]RuleOutcome, 0, len(e.ruleOutcomes)-len(removed))
	for _, outcome := range e.ruleOutcomes {
		if _, remove := removeSet[outcome.RuleID]; !remove {
			remaining = append(remaining, copyRuleOutcome(outcome))
		}
	}
	e.ruleOutcomes = remaining
	e.version++
	e.addDomainEvent(RuleOutcomeBatchRemovedEvent{e.id, e.sessionID, copyRuleOutcomes(removed), removedAt, e.version})
	return nil
}

func (e *EvaluationAggregate) RemoveRuleOutcomesIfPresent(ruleIDs []string, removedAt time.Time) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	if e.state != StateRunning {
		return ErrInvalidStateTransition
	}
	ids, err := normalizeRuleIDsForRemoval(ruleIDs)
	if err != nil {
		return err
	}
	existing := make([]string, 0, len(ids))
	for _, id := range ids {
		if e.HasRecordedRule(id) {
			existing = append(existing, id)
		}
	}
	if len(existing) == 0 {
		return nil
	}
	return e.RemoveRuleOutcomesAtomic(existing, removedAt)
}

func (e *EvaluationAggregate) ResetRuleOutcomes(resetAt time.Time) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	if e.state != StateRunning {
		return ErrInvalidStateTransition
	}
	if resetAt.IsZero() {
		return ErrRuleOutcomeResetTimeRequired
	}
	resetAt = resetAt.UTC()
	if e.startedAt == nil || resetAt.Before(*e.startedAt) {
		return ErrInvalidRuleOutcomeTimestamp
	}
	if len(e.ruleOutcomes) == 0 {
		return nil
	}
	removed := copyRuleOutcomes(e.ruleOutcomes)
	e.ruleOutcomes = nil
	e.version++
	e.addDomainEvent(RuleOutcomesResetEvent{e.id, e.sessionID, removed, resetAt, e.version})
	return nil
}

func (e *EvaluationAggregate) ResetRuleOutcomesNow() error {
	return e.ResetRuleOutcomes(time.Now().UTC())
}

func (e *EvaluationAggregate) ResetRuleOutcomesAtVersion(expectedVersion uint64, resetAt time.Time) error {
	if e == nil {
		return ErrInvalidEvaluationSnapshot
	}
	if e.version != expectedVersion {
		return ErrEvaluationVersionConflict
	}
	return e.ResetRuleOutcomes(resetAt)
}

func (e *EvaluationAggregate) HasRuleOutcomes() bool {
	return e != nil && len(e.ruleOutcomes) > 0
}
