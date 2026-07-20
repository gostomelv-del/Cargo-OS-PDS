package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

var (
	ErrPolicyIDRequired       = errors.New("policy: policy ID is required")
	ErrVersionRequired        = errors.New("policy: version is required")
	ErrSchemaVersionRequired  = errors.New("policy: schema version is required")
	ErrEffectiveFromRequired  = errors.New("policy: effective-from time is required")
	ErrInvalidEffectivePeriod = errors.New("policy: effective-until must be after effective-from")
	ErrRequiredRulesMissing   = errors.New("policy: at least one required rule is required")
	ErrDuplicateRequiredRule  = errors.New("policy: duplicate required rule")
	ErrInvalidDocument        = errors.New("policy: document must be one valid JSON value")
	ErrNonCanonicalDocument   = errors.New("policy: document is not canonical JSON")
	ErrHashMismatch           = errors.New("policy: hash mismatch")
)

type Input struct {
	PolicyID        string
	Version         string
	SchemaVersion   string
	EffectiveFrom   time.Time
	EffectiveUntil  *time.Time
	RequiredRuleIDs []string
	Document        json.RawMessage
}

type Snapshot struct {
	PolicyID        string          `json:"policy_id"`
	Version         string          `json:"version"`
	SchemaVersion   string          `json:"schema_version"`
	EffectiveFrom   time.Time       `json:"effective_from"`
	EffectiveUntil  *time.Time      `json:"effective_until,omitempty"`
	RequiredRuleIDs []string        `json:"required_rule_ids"`
	Document        json.RawMessage `json:"document"`
	Hash            string          `json:"hash"`
}

type Version struct {
	snapshot Snapshot
}

func NewVersion(input Input) (*Version, error) {
	document, err := canonicalJSON(input.Document)
	if err != nil {
		return nil, err
	}
	snapshot := Snapshot{
		PolicyID: strings.TrimSpace(input.PolicyID), Version: strings.TrimSpace(input.Version),
		SchemaVersion: strings.TrimSpace(input.SchemaVersion), EffectiveFrom: input.EffectiveFrom.UTC(),
		EffectiveUntil: copyTime(input.EffectiveUntil), RequiredRuleIDs: append([]string(nil), input.RequiredRuleIDs...),
		Document: document,
	}
	if err = normalizeAndValidate(&snapshot); err != nil {
		return nil, err
	}
	snapshot.Hash = calculateHash(snapshot)
	return &Version{snapshot: snapshot}, nil
}

func Rehydrate(snapshot Snapshot) (*Version, error) {
	copy := copySnapshot(snapshot)
	if err := normalizeAndValidate(&copy); err != nil {
		return nil, err
	}
	canonical, err := canonicalJSON(copy.Document)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, copy.Document) {
		return nil, ErrNonCanonicalDocument
	}
	if copy.Hash != calculateHash(copy) {
		return nil, ErrHashMismatch
	}
	return &Version{snapshot: copy}, nil
}

func (v *Version) Snapshot() Snapshot {
	if v == nil {
		return Snapshot{}
	}
	return copySnapshot(v.snapshot)
}

func (v *Version) IsEffectiveAt(at time.Time) bool {
	if v == nil || at.IsZero() {
		return false
	}
	at = at.UTC()
	return !at.Before(v.snapshot.EffectiveFrom) && (v.snapshot.EffectiveUntil == nil || at.Before(*v.snapshot.EffectiveUntil))
}

func normalizeAndValidate(snapshot *Snapshot) error {
	snapshot.PolicyID = strings.TrimSpace(snapshot.PolicyID)
	snapshot.Version = strings.TrimSpace(snapshot.Version)
	snapshot.SchemaVersion = strings.TrimSpace(snapshot.SchemaVersion)
	snapshot.EffectiveFrom = snapshot.EffectiveFrom.UTC()
	snapshot.EffectiveUntil = copyTime(snapshot.EffectiveUntil)
	switch {
	case snapshot.PolicyID == "":
		return ErrPolicyIDRequired
	case snapshot.Version == "":
		return ErrVersionRequired
	case snapshot.SchemaVersion == "":
		return ErrSchemaVersionRequired
	case snapshot.EffectiveFrom.IsZero():
		return ErrEffectiveFromRequired
	case snapshot.EffectiveUntil != nil && !snapshot.EffectiveUntil.After(snapshot.EffectiveFrom):
		return ErrInvalidEffectivePeriod
	case len(snapshot.RequiredRuleIDs) == 0:
		return ErrRequiredRulesMissing
	}
	seen := make(map[string]struct{}, len(snapshot.RequiredRuleIDs))
	for index, ruleID := range snapshot.RequiredRuleIDs {
		ruleID = strings.TrimSpace(ruleID)
		if ruleID == "" {
			return ErrRequiredRulesMissing
		}
		if _, found := seen[ruleID]; found {
			return fmt.Errorf("%w: %s", ErrDuplicateRequiredRule, ruleID)
		}
		seen[ruleID] = struct{}{}
		snapshot.RequiredRuleIDs[index] = ruleID
	}
	return nil
}

func calculateHash(snapshot Snapshot) string {
	envelope := struct {
		PolicyID        string          `json:"policy_id"`
		Version         string          `json:"version"`
		SchemaVersion   string          `json:"schema_version"`
		EffectiveFrom   time.Time       `json:"effective_from"`
		EffectiveUntil  *time.Time      `json:"effective_until,omitempty"`
		RequiredRuleIDs []string        `json:"required_rule_ids"`
		Document        json.RawMessage `json:"document"`
	}{snapshot.PolicyID, snapshot.Version, snapshot.SchemaVersion, snapshot.EffectiveFrom,
		snapshot.EffectiveUntil, snapshot.RequiredRuleIDs, snapshot.Document}
	payload, _ := json.Marshal(envelope)
	return fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
}

func canonicalJSON(payload []byte) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, ErrInvalidDocument
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidDocument
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidDocument
	}
	return canonical, nil
}

func copySnapshot(snapshot Snapshot) Snapshot {
	snapshot.EffectiveUntil = copyTime(snapshot.EffectiveUntil)
	snapshot.RequiredRuleIDs = append([]string(nil), snapshot.RequiredRuleIDs...)
	snapshot.Document = append(json.RawMessage(nil), snapshot.Document...)
	return snapshot
}

func copyTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := value.UTC()
	return &copy
}
