package responsibility

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"cargoos/audit"
	"cargoos/evaluation"
	"cargoos/evidence"
	"cargoos/evidencebundle"
	"cargoos/policy"
)

func TestVerifyPortableHandoverProofRecalculatesEveryBoundLayer(t *testing.T) {
	portable, trustStore, verifiedAt := portableHandoverFixture(t)
	verified, err := VerifyPortableHandoverProof(
		context.Background(), portable, trustStore, verifiedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Proof.Binding.ProofID != portable.ProofID ||
		verified.Proof.Binding.Root != portable.OutgoingSignature.BindingRoot ||
		verified.Certificate.CertificateID != portable.Certificate.CertificateID {
		t.Fatalf("incomplete verified portable handover: %#v", verified)
	}
}

func TestVerifyPortableHandoverProofRejectsIndependentLayerSubstitution(t *testing.T) {
	t.Run("audit lineage", func(t *testing.T) {
		portable, trustStore, verifiedAt := portableHandoverFixture(t)
		portable.AuditEntry.Root[0] ^= 1
		if _, err := VerifyPortableHandoverProof(
			context.Background(), portable, trustStore, verifiedAt,
		); !errors.Is(err, ErrHandoverProofBindingInvalid) {
			t.Fatalf("expected audit substitution rejection, got %v", err)
		}
	})

	t.Run("bundle manifest", func(t *testing.T) {
		portable, trustStore, verifiedAt := portableHandoverFixture(t)
		portable.Bundle.Manifest.Policy.Version = "substituted"
		if _, err := VerifyPortableHandoverProof(
			context.Background(), portable, trustStore, verifiedAt,
		); !errors.Is(err, evidencebundle.ErrBundleRootMismatch) {
			t.Fatalf("expected Bundle substitution rejection, got %v", err)
		}
	})

	t.Run("incoming participant signature", func(t *testing.T) {
		portable, trustStore, verifiedAt := portableHandoverFixture(t)
		portable.IncomingSignature.Value = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		if _, err := VerifyPortableHandoverProof(
			context.Background(), portable, trustStore, verifiedAt,
		); !errors.Is(err, ErrHandoverSignatureValue) {
			t.Fatalf("expected Participant signature rejection, got %v", err)
		}
	})
}

func portableHandoverFixture(t *testing.T) (PortableHandoverProof, *policy.MemoryTrustStore, time.Time) {
	t.Helper()
	base := time.Date(2026, 8, 2, 10, 0, 0, 0, time.UTC)
	sessionID := uuid.New()
	evidenceID := uuid.New()
	observation, err := evidence.NewObject(evidence.Input{
		EvidenceID: evidenceID, SessionID: sessionID,
		SourceID: "scale-17", SourceType: "WEIGHT_SENSOR", EvidenceType: evidence.TypeWeight,
		ObservedAt: base, ReceivedAt: base.Add(time.Second),
		Payload:       json.RawMessage(`{"unit":"kg","value":25}`),
		SchemaVersion: "evidence.v1", RuntimeVersion: "cargoos-pds.test", AcquisitionMethod: "HTTP",
	})
	if err != nil {
		t.Fatal(err)
	}
	version, err := policy.NewVersion(policy.Input{
		PolicyID: "cargo-transfer", Version: "1.0.0", SchemaVersion: "policy.document.v1",
		EffectiveFrom: base.Add(-time.Hour), RequiredRuleIDs: []string{"weight"},
		Document: json.RawMessage(`{"evidence_qualification":{"version":"qualification.v1","trusted_sources":["scale-17"],"allowed_types":["WEIGHT"],"allowed_acquisition_methods":["HTTP"]},"rules":[{"rule_id":"weight","operator":"RANGE","selector":{"evidence_type":"WEIGHT","json_pointer":"/value"},"minimum":"0","maximum":"25"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	policySnapshot := version.Snapshot()
	completedAt := base.Add(3 * time.Second)
	trace := evaluation.DecisionTrace{
		EvaluationID: uuid.New(), SessionID: sessionID, Version: 8,
		State: evaluation.StateCompleted, Result: evaluation.ResultVerified,
		RequiredRuleIDs: []string{"weight"},
		RuleOutcomes: []evaluation.RuleOutcome{{
			RuleID: "weight", Status: evaluation.RuleOutcomePass, EvaluatedAt: base.Add(2 * time.Second),
		}},
		CreatedAt: base, CompletedAt: &completedAt,
		EvidenceBinding: &evaluation.EvidenceSetBinding{
			SessionID: sessionID, Status: evaluation.EvidenceQualified,
			PolicyVersion: "qualification.v1", QualifiedAt: base.Add(2 * time.Second),
			Evidence: []evaluation.EvidenceReference{{EvidenceID: evidenceID, Status: evaluation.EvidenceQualified}},
		},
		PolicyBinding: &evaluation.PolicyBinding{
			PolicyID: policySnapshot.PolicyID, Version: policySnapshot.Version,
			Hash: policySnapshot.Hash, BoundAt: base,
		},
	}
	bundle, err := evidencebundle.BuildWithPolicySnapshot(evidencebundle.BuildInput{
		BundleID: uuid.New(), GeneratedAt: base.Add(4 * time.Second), Trace: trace,
		Evidence: []evidence.Snapshot{observation.Snapshot()},
	}, policySnapshot)
	if err != nil {
		t.Fatal(err)
	}
	report, err := evidencebundle.VerifyDecision(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}

	bundleKey := portableTestKey("bundle-authority", "bundle-key", base)
	timestampKey := portableTestKey("timestamp-authority", "timestamp-key", base)
	verifierKey := portableTestKey("offline-verifier", "verifier-key", base)
	outgoingKey := portableTestKey("vehicle", "vehicle-key", base)
	incomingKey := portableTestKey("warehouse", "warehouse-key", base)
	trustStore, err := policy.NewMemoryTrustStore(
		bundleKey.verification, timestampKey.verification, verifierKey.verification,
		outgoingKey.verification, incomingKey.verification,
	)
	if err != nil {
		t.Fatal(err)
	}

	bundleSignature, err := evidencebundle.NewSignature(
		bundle, bundleKey.verification.SignerID, bundleKey.verification.KeyID, base.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	bundlePayload, err := evidencebundle.SigningPayload(bundle, bundleSignature)
	if err != nil {
		t.Fatal(err)
	}
	bundleSignature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(bundleKey.private, bundlePayload))
	verifiedBundle, err := evidencebundle.VerifySignature(
		context.Background(), bundle, bundleSignature, trustStore, base.Add(61*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}

	timestamp, err := evidencebundle.NewTrustedTimestamp(
		verifiedBundle, timestampKey.verification.SignerID, timestampKey.verification.KeyID,
		"handover-ts-1", base.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	timestampPayload, err := evidencebundle.TimestampSigningPayload(timestamp)
	if err != nil {
		t.Fatal(err)
	}
	timestamp.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(timestampKey.private, timestampPayload))
	timestamped, err := evidencebundle.VerifyTrustedTimestamp(
		context.Background(), verifiedBundle, timestamp, trustStore, base.Add(121*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := evidencebundle.NewVerificationCertificate(
		report, timestamped, uuid.New(), verifierKey.verification.SignerID,
		verifierKey.verification.KeyID, base.Add(3*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	certificatePayload, err := evidencebundle.VerificationCertificateSigningPayload(certificate)
	if err != nil {
		t.Fatal(err)
	}
	certificate.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(verifierKey.private, certificatePayload))

	transfer := TransferredEvent{
		ObjectID: "cargo-42", FromParticipantID: "vehicle", ToParticipantID: "warehouse",
		TransferredAt: base.Add(5 * time.Second), Version: 2,
	}
	transferRoot, err := TransferredEventRoot(transfer)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := audit.NewEntry(
		2, audit.RecordResponsibilityHandover, [32]byte{9}, transferRoot, transfer.TransferredAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	proofID := uuid.New()
	binding, err := NewHandoverProofBinding(proofID, transfer, entry, bundle.Manifest, certificate)
	if err != nil {
		t.Fatal(err)
	}
	outgoing := signedPortableParticipant(t, binding, HandoverSignerOutgoing, outgoingKey, base.Add(4*time.Minute))
	incoming := signedPortableParticipant(t, binding, HandoverSignerIncoming, incomingKey, base.Add(4*time.Minute))
	return PortableHandoverProof{
		ProofID: proofID, Transfer: transfer, AuditEntry: entry, Bundle: bundle,
		BundleSignature: bundleSignature, Timestamp: timestamp, Certificate: certificate,
		OutgoingSignature: outgoing, IncomingSignature: incoming,
	}, trustStore, base.Add(5 * time.Minute)
}

type portableKey struct {
	private      ed25519.PrivateKey
	verification policy.VerificationKey
}

func portableTestKey(signerID, keyID string, validFrom time.Time) portableKey {
	seed := sha256.Sum256([]byte(signerID + ":" + keyID))
	private := ed25519.NewKeyFromSeed(seed[:])
	return portableKey{
		private: private,
		verification: policy.VerificationKey{
			SignerID: signerID, KeyID: keyID, Algorithm: policy.AlgorithmEd25519,
			PublicKey: private.Public().(ed25519.PublicKey), ValidFrom: validFrom,
		},
	}
}

func signedPortableParticipant(
	t *testing.T,
	binding HandoverProofBinding,
	role HandoverSignerRole,
	key portableKey,
	signedAt time.Time,
) HandoverProofSignature {
	t.Helper()
	signature, err := NewHandoverProofSignature(
		binding, role, key.verification.SignerID, key.verification.KeyID, signedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := HandoverProofSigningPayload(signature)
	if err != nil {
		t.Fatal(err)
	}
	signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(key.private, payload[:]))
	return signature
}
