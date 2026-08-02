package responsibility

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/audit"
	"cargoos/evaluation"
	"cargoos/evidence"
	"cargoos/evidencebundle"
)

func TestHandoverProofBindingBindsTransferLedgerBundlePolicyAndCertificate(t *testing.T) {
	fixture := handoverProofFixture(t)
	binding, err := NewHandoverProofBinding(
		fixture.proofID, fixture.event, fixture.entry, fixture.manifest, fixture.certificate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err = binding.Validate(); err != nil {
		t.Fatal(err)
	}
	if binding.TransferRoot != fixture.entry.RecordRoot || binding.BundleRoot == ([32]byte{}) ||
		binding.CertificateRoot == ([32]byte{}) || binding.Root == ([32]byte{}) {
		t.Fatalf("incomplete handover proof binding: %#v", binding)
	}
	tampered := binding
	tampered.AuditPreviousRoot[0] ^= 1
	if tampered.Validate() == nil {
		t.Fatal("expected audit-lineage substitution rejection")
	}
	tampered = binding
	tampered.PolicyHash = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if tampered.Validate() == nil {
		t.Fatal("expected Policy substitution rejection")
	}
}

func TestHandoverProofBindingRejectsCrossArtifactSubstitution(t *testing.T) {
	fixture := handoverProofFixture(t)
	fixture.entry.RecordRoot[0] ^= 1
	if _, err := NewHandoverProofBinding(
		fixture.proofID, fixture.event, fixture.entry, fixture.manifest, fixture.certificate,
	); err == nil {
		t.Fatal("expected transfer/audit mismatch rejection")
	}
	fixture = handoverProofFixture(t)
	fixture.certificate.BundleID = uuid.New()
	if _, err := NewHandoverProofBinding(
		fixture.proofID, fixture.event, fixture.entry, fixture.manifest, fixture.certificate,
	); err == nil {
		t.Fatal("expected Bundle/certificate mismatch rejection")
	}
}

type handoverProofTestFixture struct {
	proofID     uuid.UUID
	event       TransferredEvent
	entry       audit.Entry
	manifest    evidencebundle.Manifest
	certificate evidencebundle.VerificationCertificate
}

func handoverProofFixture(t *testing.T) handoverProofTestFixture {
	t.Helper()
	transferredAt := time.Date(2026, 8, 2, 10, 0, 0, 0, time.UTC)
	event := TransferredEvent{
		ObjectID: "cargo-42", FromParticipantID: "vehicle", ToParticipantID: "warehouse",
		TransferredAt: transferredAt, Version: 2,
	}
	transferRoot, err := TransferredEventRoot(event)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := audit.NewEntry(2, audit.RecordResponsibilityHandover, [32]byte{9}, transferRoot, transferredAt)
	if err != nil {
		t.Fatal(err)
	}
	manifest := evidencebundle.Manifest{
		SchemaVersion: evidencebundle.SchemaVersion, BundleID: uuid.New(), EvaluationID: uuid.New(),
		SessionID: uuid.New(), GeneratedAt: transferredAt.Add(time.Second), HashAlgorithm: evidencebundle.HashAlgorithm,
		Policy: evidencebundle.PolicyReference{
			PolicyID: "handover", Version: "1", Hash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}
	bundle := handoverProofBundle(t, manifest)
	manifest = bundle.Manifest
	certificate := evidencebundle.VerificationCertificate{
		SchemaVersion: evidencebundle.VerificationCertificateSchema, CertificateID: uuid.New(),
		BundleID: manifest.BundleID, EvaluationID: manifest.EvaluationID, BundleRoot: manifest.BundleRoot,
		Policy: manifest.Policy, StoredResult: evaluation.ResultVerified,
		RecalculatedResult: evaluation.ResultVerified,
		Outcomes:           []evidencebundle.RecalculatedOutcome{{RuleID: "handover", Status: evaluation.RuleOutcomePass}},
		TimestampHash:      "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		TimestampIssuedAt:  transferredAt.Add(2 * time.Second), VerifierID: "independent-verifier",
		KeyID: "verifier-key", IssuedAt: transferredAt.Add(3 * time.Second),
		SignatureAlgorithm: evidencebundle.SignatureAlgorithm, HashAlgorithm: evidencebundle.HashAlgorithm,
		Value: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}
	return handoverProofTestFixture{
		proofID: uuid.New(), event: event, entry: entry, manifest: manifest, certificate: certificate,
	}
}

func handoverProofBundle(t *testing.T, manifest evidencebundle.Manifest) evidencebundle.Bundle {
	t.Helper()
	evidenceID := uuid.New()
	object, err := evidence.NewObject(evidence.Input{
		EvidenceID: evidenceID, SessionID: manifest.SessionID,
		SourceID: "handover-contact", SourceType: "CONTACT_SENSOR",
		EvidenceType: evidence.TypeContact, ObservedAt: manifest.GeneratedAt.Add(-3 * time.Second),
		ReceivedAt: manifest.GeneratedAt.Add(-2 * time.Second), Payload: json.RawMessage(`{"contact":true}`),
		SchemaVersion: "evidence.v1", RuntimeVersion: "cargoos-pds.test", AcquisitionMethod: "CONTACT",
	})
	if err != nil {
		t.Fatal(err)
	}
	trace := evaluation.DecisionTrace{
		EvaluationID: manifest.EvaluationID, SessionID: manifest.SessionID, Version: 1,
		State: evaluation.StateCompleted, Result: evaluation.ResultVerified,
		RequiredRuleIDs: []string{"handover"},
		RuleOutcomes: []evaluation.RuleOutcome{{
			RuleID: "handover", Status: evaluation.RuleOutcomePass,
			EvaluatedAt: manifest.GeneratedAt.Add(-time.Second),
		}},
		CreatedAt: manifest.GeneratedAt.Add(-3 * time.Second), CompletedAt: timePointer(manifest.GeneratedAt.Add(-time.Second)),
		EvidenceBinding: &evaluation.EvidenceSetBinding{
			SessionID: manifest.SessionID, Status: evaluation.EvidenceQualified,
			PolicyVersion: "qualification.v1", QualifiedAt: manifest.GeneratedAt.Add(-2 * time.Second),
			Evidence: []evaluation.EvidenceReference{{EvidenceID: evidenceID, Status: evaluation.EvidenceQualified}},
		},
		PolicyBinding: &evaluation.PolicyBinding{
			PolicyID: manifest.Policy.PolicyID, Version: manifest.Policy.Version,
			Hash: manifest.Policy.Hash, BoundAt: manifest.GeneratedAt.Add(-2 * time.Second),
		},
	}
	bundle, err := evidencebundle.Build(evidencebundle.BuildInput{
		BundleID: manifest.BundleID, GeneratedAt: manifest.GeneratedAt, Trace: trace,
		Evidence: []evidence.Snapshot{object.Snapshot()},
	})
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func timePointer(value time.Time) *time.Time { return &value }
