package evidencebundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
	"cargoos/evidence"
)

var (
	ErrBundleIdentityRequired  = errors.New("evidencebundle: bundle identity is required")
	ErrFinalDecisionRequired   = errors.New("evidencebundle: final decision is required")
	ErrPolicyBindingRequired   = errors.New("evidencebundle: policy binding is required")
	ErrEvidenceBindingRequired = errors.New("evidencebundle: evidence binding is required")
	ErrEvidenceObjectMismatch  = errors.New("evidencebundle: evidence object does not match decision binding")
	ErrObjectPathInvalid       = errors.New("evidencebundle: object path is invalid")
	ErrObjectDigestMismatch    = errors.New("evidencebundle: object digest mismatch")
	ErrBundleRootMismatch      = errors.New("evidencebundle: bundle root mismatch")
)

const (
	SchemaVersion = "cargoos.evidence-bundle.manifest.v1"
	HashAlgorithm = "SHA-256"
)

var sha256Pattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Object struct {
	Path      string          `json:"path"`
	MediaType string          `json:"media_type"`
	Payload   json.RawMessage `json:"-"`
}

type ObjectDescriptor struct {
	Path      string `json:"path"`
	MediaType string `json:"media_type"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

type PolicyReference struct {
	PolicyID string `json:"policy_id"`
	Version  string `json:"version"`
	Hash     string `json:"hash"`
}

type Manifest struct {
	SchemaVersion string             `json:"schema_version"`
	BundleID      uuid.UUID          `json:"bundle_id"`
	EvaluationID  uuid.UUID          `json:"evaluation_id"`
	SessionID     uuid.UUID          `json:"session_id"`
	GeneratedAt   time.Time          `json:"generated_at"`
	HashAlgorithm string             `json:"hash_algorithm"`
	Policy        PolicyReference    `json:"policy"`
	Objects       []ObjectDescriptor `json:"objects"`
	BundleRoot    string             `json:"bundle_root"`
}

type Bundle struct {
	Manifest Manifest
	Objects  []Object
}

type BuildInput struct {
	BundleID    uuid.UUID
	GeneratedAt time.Time
	Trace       evaluation.DecisionTrace
	Evidence    []evidence.Snapshot
}

func Build(input BuildInput) (Bundle, error) {
	if input.BundleID == uuid.Nil || input.GeneratedAt.IsZero() {
		return Bundle{}, ErrBundleIdentityRequired
	}
	trace := input.Trace
	if trace.EvaluationID == uuid.Nil || trace.SessionID == uuid.Nil ||
		(trace.State != evaluation.StateCompleted && trace.State != evaluation.StateExpired) {
		return Bundle{}, ErrFinalDecisionRequired
	}
	var finalizedAt *time.Time
	if trace.State == evaluation.StateCompleted {
		finalizedAt = trace.CompletedAt
	} else {
		finalizedAt = trace.ExpiredAt
	}
	if finalizedAt == nil || input.GeneratedAt.Before(*finalizedAt) {
		return Bundle{}, ErrFinalDecisionRequired
	}
	if trace.PolicyBinding == nil {
		return Bundle{}, ErrPolicyBindingRequired
	}
	if strings.TrimSpace(trace.PolicyBinding.PolicyID) == "" ||
		strings.TrimSpace(trace.PolicyBinding.Version) == "" ||
		!sha256Pattern.MatchString(trace.PolicyBinding.Hash) {
		return Bundle{}, ErrPolicyBindingRequired
	}
	if trace.EvidenceBinding == nil {
		return Bundle{}, ErrEvidenceBindingRequired
	}
	if trace.EvidenceBinding.SessionID != trace.SessionID {
		return Bundle{}, ErrEvidenceBindingRequired
	}
	objects, err := buildObjects(trace, input.Evidence)
	if err != nil {
		return Bundle{}, err
	}
	descriptors := make([]ObjectDescriptor, 0, len(objects))
	for _, object := range objects {
		descriptors = append(descriptors, describe(object))
	}
	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		BundleID:      input.BundleID,
		EvaluationID:  trace.EvaluationID,
		SessionID:     trace.SessionID,
		GeneratedAt:   input.GeneratedAt.UTC(),
		HashAlgorithm: HashAlgorithm,
		Policy: PolicyReference{
			PolicyID: trace.PolicyBinding.PolicyID,
			Version:  trace.PolicyBinding.Version,
			Hash:     trace.PolicyBinding.Hash,
		},
		Objects: descriptors,
	}
	manifest.BundleRoot = calculateRoot(manifest)
	return Bundle{Manifest: manifest, Objects: copyObjects(objects)}, nil
}

func Verify(bundle Bundle) error {
	manifest := bundle.Manifest
	if manifest.SchemaVersion != SchemaVersion ||
		manifest.BundleID == uuid.Nil ||
		manifest.EvaluationID == uuid.Nil ||
		manifest.SessionID == uuid.Nil ||
		manifest.GeneratedAt.IsZero() ||
		manifest.HashAlgorithm != HashAlgorithm {
		return ErrBundleIdentityRequired
	}
	if calculateRoot(manifest) != manifest.BundleRoot {
		return ErrBundleRootMismatch
	}
	objects := copyObjects(bundle.Objects)
	sort.Slice(objects, func(i, j int) bool { return objects[i].Path < objects[j].Path })
	if len(objects) != len(manifest.Objects) {
		return ErrObjectDigestMismatch
	}
	for index, descriptor := range manifest.Objects {
		object := objects[index]
		if err := validateObject(object); err != nil {
			return err
		}
		if actual := describe(object); actual != descriptor {
			return fmt.Errorf("%w: %s", ErrObjectDigestMismatch, descriptor.Path)
		}
	}
	return nil
}

func CanonicalManifest(manifest Manifest) ([]byte, error) {
	if manifest.SchemaVersion != SchemaVersion {
		return nil, ErrBundleIdentityRequired
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func buildObjects(trace evaluation.DecisionTrace, snapshots []evidence.Snapshot) ([]Object, error) {
	byID := make(map[uuid.UUID]evidence.Snapshot, len(snapshots))
	for _, snapshot := range snapshots {
		object, err := evidence.Rehydrate(snapshot)
		if err != nil {
			return nil, err
		}
		snapshot = object.Snapshot()
		if snapshot.SessionID != trace.SessionID {
			return nil, ErrEvidenceObjectMismatch
		}
		if _, exists := byID[snapshot.EvidenceID]; exists {
			return nil, ErrEvidenceObjectMismatch
		}
		byID[snapshot.EvidenceID] = snapshot
	}
	if len(byID) != len(trace.EvidenceBinding.Evidence) {
		return nil, ErrEvidenceObjectMismatch
	}

	tracePayload, err := json.Marshal(trace)
	if err != nil {
		return nil, err
	}
	policyPayload, err := json.Marshal(PolicyReference{
		PolicyID: trace.PolicyBinding.PolicyID,
		Version:  trace.PolicyBinding.Version,
		Hash:     trace.PolicyBinding.Hash,
	})
	if err != nil {
		return nil, err
	}
	objects := []Object{
		{Path: "decision-trace.json", MediaType: "application/json", Payload: tracePayload},
		{Path: "policy/reference.json", MediaType: "application/json", Payload: policyPayload},
	}
	for _, reference := range trace.EvidenceBinding.Evidence {
		snapshot, exists := byID[reference.EvidenceID]
		if !exists {
			return nil, ErrEvidenceObjectMismatch
		}
		payload, marshalErr := json.Marshal(snapshot)
		if marshalErr != nil {
			return nil, marshalErr
		}
		objects = append(objects, Object{
			Path:      "evidence/" + reference.EvidenceID.String() + ".json",
			MediaType: "application/json",
			Payload:   payload,
		})
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].Path < objects[j].Path })
	for _, object := range objects {
		if err = validateObject(object); err != nil {
			return nil, err
		}
	}
	return objects, nil
}

func validateObject(object Object) error {
	path := strings.TrimSpace(object.Path)
	if path == "" || path != object.Path || strings.HasPrefix(path, "/") ||
		strings.Contains(path, "..") || strings.Contains(path, "\\") {
		return ErrObjectPathInvalid
	}
	if strings.TrimSpace(object.MediaType) == "" || len(object.Payload) == 0 ||
		!json.Valid(object.Payload) {
		return ErrObjectDigestMismatch
	}
	return nil
}

func describe(object Object) ObjectDescriptor {
	return ObjectDescriptor{
		Path:      object.Path,
		MediaType: object.MediaType,
		Size:      int64(len(object.Payload)),
		Digest:    digest(object.Payload),
	}
}

func calculateRoot(manifest Manifest) string {
	manifest.BundleRoot = ""
	payload, _ := json.Marshal(manifest)
	return digest(payload)
}

func digest(payload []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
}

func copyObjects(source []Object) []Object {
	result := make([]Object, len(source))
	for index, object := range source {
		result[index] = object
		result[index].Payload = bytes.Clone(object.Payload)
	}
	return result
}
