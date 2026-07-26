package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

type recordingActivatedRegistry struct {
	calls     int
	activated *ActivatedVersion
	err       error
}

type recordingDocumentValidator struct {
	calls int
	err   error
}

func (v *recordingDocumentValidator) ValidatePolicyDocument(_ context.Context, _ *Version) error {
	v.calls++
	return v.err
}

func (r *recordingActivatedRegistry) Add(_ context.Context, activated *ActivatedVersion) error {
	r.calls++
	r.activated = activated
	return r.err
}

func admissionFixture(t *testing.T) (*Version, Signature, ApprovalRecord, *Verifier, time.Time) {
	t.Helper()
	at := time.Date(2026, 7, 26, 8, 0, 0, 0, time.UTC)
	version, err := NewVersion(policyInput("1.0.0", at, nil))
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	store, err := NewMemoryTrustStore(VerificationKey{
		SignerID: "policy-authority", KeyID: "key-1", Algorithm: AlgorithmEd25519,
		PublicKey: privateKey.Public().(ed25519.PublicKey), ValidFrom: at.Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(store)
	if err != nil {
		t.Fatal(err)
	}
	signature := Signature{
		SignerID: "policy-authority", KeyID: "key-1", Algorithm: AlgorithmEd25519,
		SignedAt: at.Add(-time.Minute),
	}
	payload, err := SigningPayload(version, signature)
	if err != nil {
		t.Fatal(err)
	}
	signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	snapshot := version.Snapshot()
	approval := ApprovalRecord{
		PolicyID: snapshot.PolicyID, Version: snapshot.Version, PolicyHash: snapshot.Hash,
		ApprovedBy: "policy-review-board", ApprovedAt: at.Add(-time.Second),
	}
	return version, signature, approval, verifier, at
}

func TestAdmissionServiceVerifiesApprovesAndPersistsOnce(t *testing.T) {
	version, signature, approval, verifier, at := admissionFixture(t)
	registry := &recordingActivatedRegistry{}
	validator := &recordingDocumentValidator{}
	service, err := NewAdmissionService(verifier, validator, registry)
	if err != nil {
		t.Fatal(err)
	}
	activated, err := service.Admit(context.Background(), version, signature, approval, at, at)
	if err != nil {
		t.Fatal(err)
	}
	if registry.calls != 1 || registry.activated != activated {
		t.Fatalf("expected one exact activated-version write, got calls=%d value=%p", registry.calls, registry.activated)
	}
	if validator.calls != 1 {
		t.Fatalf("expected one document validation, got %d", validator.calls)
	}
	if activated.VerifiedVersion().Version().Snapshot().Hash != version.Snapshot().Hash {
		t.Fatal("admission changed immutable policy identity")
	}
}

func TestAdmissionServiceDoesNotPersistFailedVerificationOrApproval(t *testing.T) {
	version, signature, approval, verifier, at := admissionFixture(t)
	registry := &recordingActivatedRegistry{}
	service, _ := NewAdmissionService(verifier, &recordingDocumentValidator{}, registry)

	invalidSignature := signature
	invalidSignature.Value = "invalid"
	if _, err := service.Admit(context.Background(), version, invalidSignature, approval, at, at); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected signature rejection, got %v", err)
	}
	if registry.calls != 0 {
		t.Fatal("failed signature reached registry")
	}

	invalidApproval := approval
	invalidApproval.PolicyHash = "sha256:wrong"
	if _, err := service.Admit(context.Background(), version, signature, invalidApproval, at, at); !errors.Is(err, ErrApprovalIdentityMismatch) {
		t.Fatalf("expected approval rejection, got %v", err)
	}
	if registry.calls != 0 {
		t.Fatal("failed approval reached registry")
	}
}

func TestAdmissionServiceRejectsInvalidOrderingAndRegistryFailure(t *testing.T) {
	version, signature, approval, verifier, at := admissionFixture(t)
	registry := &recordingActivatedRegistry{err: ErrEffectiveOverlap}
	service, _ := NewAdmissionService(verifier, &recordingDocumentValidator{}, registry)

	if _, err := service.Admit(context.Background(), version, signature, approval, at.Add(time.Second), at); !errors.Is(err, ErrVerificationAfterActivation) {
		t.Fatalf("expected ordering rejection, got %v", err)
	}
	if registry.calls != 0 {
		t.Fatal("invalid admission ordering reached registry")
	}

	if _, err := service.Admit(context.Background(), version, signature, approval, at, at); !errors.Is(err, ErrEffectiveOverlap) {
		t.Fatalf("expected registry failure, got %v", err)
	}
	if registry.calls != 1 {
		t.Fatalf("expected one registry attempt, got %d", registry.calls)
	}
}

func TestAdmissionServiceDoesNotActivateInvalidDocument(t *testing.T) {
	version, signature, approval, verifier, at := admissionFixture(t)
	registry := &recordingActivatedRegistry{}
	validator := &recordingDocumentValidator{err: ErrInvalidDocument}
	service, err := NewAdmissionService(verifier, validator, registry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Admit(context.Background(), version, signature, approval, at, at); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("expected document rejection, got %v", err)
	}
	if validator.calls != 1 {
		t.Fatalf("expected one document validation, got %d", validator.calls)
	}
	if registry.calls != 0 {
		t.Fatal("invalid policy document reached registry")
	}
}

func TestAdmissionServiceRequiresDependencies(t *testing.T) {
	registry := &recordingActivatedRegistry{}
	validator := &recordingDocumentValidator{}
	if _, err := NewAdmissionService(nil, validator, registry); !errors.Is(err, ErrTrustStoreRequired) {
		t.Fatalf("expected verifier requirement, got %v", err)
	}
	_, _, _, verifier, _ := admissionFixture(t)
	if _, err := NewAdmissionService(verifier, nil, registry); !errors.Is(err, ErrDocumentValidatorRequired) {
		t.Fatalf("expected document validator requirement, got %v", err)
	}
	if _, err := NewAdmissionService(verifier, validator, nil); !errors.Is(err, ErrPolicyRegistryRequired) {
		t.Fatalf("expected registry requirement, got %v", err)
	}
}
