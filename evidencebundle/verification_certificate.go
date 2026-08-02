package evidencebundle

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"cargoos/evaluation"
	"cargoos/policy"
)

const (
	VerificationCertificateSchema = "cargoos.evidence-bundle.verification-certificate.v1"
	verificationCertificateDomain = "cargoos:evidence-bundle-verification-certificate:v1"
)

var (
	ErrVerificationCertificateRequired = errors.New("evidencebundle: verification certificate is required")
	ErrVerificationCertificateBinding  = errors.New("evidencebundle: verification certificate binding is invalid")
	ErrVerificationCertificateTime     = errors.New("evidencebundle: verification certificate time is invalid")
	ErrVerificationCertificateInvalid  = errors.New("evidencebundle: verification certificate signature is invalid")
)

type VerificationCertificate struct {
	SchemaVersion      string                        `json:"schema_version"`
	CertificateID      uuid.UUID                     `json:"certificate_id"`
	BundleID           uuid.UUID                     `json:"bundle_id"`
	EvaluationID       uuid.UUID                     `json:"evaluation_id"`
	BundleRoot         string                        `json:"bundle_root"`
	Policy             PolicyReference               `json:"policy"`
	StoredResult       evaluation.VerificationResult `json:"stored_result"`
	RecalculatedResult evaluation.VerificationResult `json:"recalculated_result"`
	Outcomes           []RecalculatedOutcome         `json:"outcomes"`
	TimestampHash      string                        `json:"timestamp_hash"`
	TimestampIssuedAt  time.Time                     `json:"timestamp_issued_at"`
	VerifierID         string                        `json:"verifier_id"`
	KeyID              string                        `json:"key_id"`
	IssuedAt           time.Time                     `json:"issued_at"`
	SignatureAlgorithm string                        `json:"signature_algorithm"`
	HashAlgorithm      string                        `json:"hash_algorithm"`
	Value              string                        `json:"value"`
}

// NewVerificationCertificate creates the immutable metadata that an external
// verifier signs after successful independent decision verification.
func NewVerificationCertificate(report IndependentVerificationReport, timestamped *TimestampedBundle, certificateID uuid.UUID, verifierID, keyID string, issuedAt time.Time) (VerificationCertificate, error) {
	if !report.Verified || timestamped == nil || timestamped.verified == nil {
		return VerificationCertificate{}, ErrVerificationCertificateBinding
	}
	verifierID = strings.TrimSpace(verifierID)
	keyID = strings.TrimSpace(keyID)
	issuedAt = issuedAt.UTC()
	bundle := timestamped.verified.bundle
	if certificateID == uuid.Nil || verifierID == "" || keyID == "" ||
		report.BundleID != bundle.Manifest.BundleID || report.EvaluationID != bundle.Manifest.EvaluationID ||
		report.Policy != bundle.Manifest.Policy || report.StoredResult != report.RecalculatedResult {
		return VerificationCertificate{}, ErrVerificationCertificateBinding
	}
	if issuedAt.IsZero() || issuedAt.Before(timestamped.timestamp.IssuedAt.UTC()) {
		return VerificationCertificate{}, ErrVerificationCertificateTime
	}
	timestampPayload, err := CanonicalTimestamp(timestamped.timestamp)
	if err != nil {
		return VerificationCertificate{}, err
	}
	return VerificationCertificate{
		SchemaVersion: VerificationCertificateSchema, CertificateID: certificateID,
		BundleID: report.BundleID, EvaluationID: report.EvaluationID,
		BundleRoot: bundle.Manifest.BundleRoot, Policy: report.Policy,
		StoredResult: report.StoredResult, RecalculatedResult: report.RecalculatedResult,
		Outcomes: copyRecalculatedOutcomes(report.Outcomes), TimestampHash: digest(timestampPayload),
		TimestampIssuedAt: timestamped.timestamp.IssuedAt.UTC(), VerifierID: verifierID, KeyID: keyID,
		IssuedAt: issuedAt, SignatureAlgorithm: SignatureAlgorithm, HashAlgorithm: HashAlgorithm,
	}, nil
}

func VerificationCertificateSigningPayload(certificate VerificationCertificate) ([]byte, error) {
	if err := validateVerificationCertificate(certificate, false); err != nil {
		return nil, err
	}
	copy := certificate
	copy.Value = ""
	payload, err := json.Marshal(struct {
		Domain      string                  `json:"domain"`
		Certificate VerificationCertificate `json:"certificate"`
	}{Domain: verificationCertificateDomain, Certificate: copy})
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(payload)
	return hash[:], nil
}

// VerifyVerificationCertificate validates the certificate signature and
// independently repeats the decision verification against the timestamped
// Bundle before returning a defensive certificate copy.
func VerifyVerificationCertificate(ctx context.Context, timestamped *TimestampedBundle, certificate VerificationCertificate, trustStore policy.TrustStore, verifiedAt time.Time) (VerificationCertificate, error) {
	if timestamped == nil || timestamped.verified == nil || trustStore == nil {
		return VerificationCertificate{}, ErrVerificationCertificateRequired
	}
	verifiedAt = verifiedAt.UTC()
	if verifiedAt.IsZero() || verifiedAt.Before(certificate.IssuedAt.UTC()) || certificate.IssuedAt.Before(timestamped.timestamp.IssuedAt.UTC()) {
		return VerificationCertificate{}, ErrVerificationCertificateTime
	}
	if err := validateVerificationCertificate(certificate, true); err != nil {
		return VerificationCertificate{}, err
	}
	bundle := timestamped.verified.bundle
	timestampPayload, err := CanonicalTimestamp(timestamped.timestamp)
	if err != nil || certificate.BundleID != bundle.Manifest.BundleID ||
		certificate.EvaluationID != bundle.Manifest.EvaluationID || certificate.BundleRoot != bundle.Manifest.BundleRoot ||
		certificate.Policy != bundle.Manifest.Policy || certificate.TimestampHash != digest(timestampPayload) ||
		!certificate.TimestampIssuedAt.Equal(timestamped.timestamp.IssuedAt.UTC()) {
		return VerificationCertificate{}, ErrVerificationCertificateBinding
	}
	report, err := VerifyDecision(ctx, bundle)
	if err != nil || report.StoredResult != certificate.StoredResult ||
		report.RecalculatedResult != certificate.RecalculatedResult || !sameRecalculatedOutcomes(report.Outcomes, certificate.Outcomes) {
		return VerificationCertificate{}, ErrVerificationCertificateBinding
	}
	key, err := trustStore.ResolveVerificationKey(ctx, certificate.VerifierID, certificate.KeyID)
	if err != nil {
		return VerificationCertificate{}, err
	}
	if key.SignerID != certificate.VerifierID || key.KeyID != certificate.KeyID {
		return VerificationCertificate{}, policy.ErrVerificationKeyAbsent
	}
	if key.Algorithm != SignatureAlgorithm {
		return VerificationCertificate{}, policy.ErrUnsupportedAlgorithm
	}
	if !key.ValidFrom.IsZero() && certificate.IssuedAt.Before(key.ValidFrom.UTC()) {
		return VerificationCertificate{}, policy.ErrKeyNotYetValid
	}
	if key.ValidUntil != nil && (!certificate.IssuedAt.Before(key.ValidUntil.UTC()) || !verifiedAt.Before(key.ValidUntil.UTC())) {
		return VerificationCertificate{}, policy.ErrKeyExpired
	}
	if key.RevokedAt != nil && (!certificate.IssuedAt.Before(key.RevokedAt.UTC()) || !verifiedAt.Before(key.RevokedAt.UTC())) {
		return VerificationCertificate{}, policy.ErrKeyRevoked
	}
	value, decodeErr := base64.StdEncoding.DecodeString(certificate.Value)
	payload, payloadErr := VerificationCertificateSigningPayload(certificate)
	if decodeErr != nil || payloadErr != nil || len(value) != ed25519.SignatureSize || len(key.PublicKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(ed25519.PublicKey(key.PublicKey), payload, value) {
		return VerificationCertificate{}, ErrVerificationCertificateInvalid
	}
	return copyVerificationCertificate(certificate), nil
}

func CanonicalVerificationCertificate(certificate VerificationCertificate) ([]byte, error) {
	if err := validateVerificationCertificate(certificate, true); err != nil {
		return nil, err
	}
	return json.Marshal(certificate)
}

func validateVerificationCertificate(certificate VerificationCertificate, requireValue bool) error {
	if certificate.SchemaVersion != VerificationCertificateSchema || certificate.CertificateID == uuid.Nil ||
		certificate.BundleID == uuid.Nil || certificate.EvaluationID == uuid.Nil || !sha256Pattern.MatchString(certificate.BundleRoot) ||
		certificate.Policy.PolicyID == "" || certificate.Policy.Version == "" || !sha256Pattern.MatchString(certificate.Policy.Hash) ||
		certificate.StoredResult != certificate.RecalculatedResult || certificate.StoredResult == evaluation.ResultUnknown ||
		len(certificate.Outcomes) == 0 || !sha256Pattern.MatchString(certificate.TimestampHash) || certificate.TimestampIssuedAt.IsZero() ||
		certificate.VerifierID == "" || certificate.VerifierID != strings.TrimSpace(certificate.VerifierID) ||
		certificate.KeyID == "" || certificate.KeyID != strings.TrimSpace(certificate.KeyID) || certificate.IssuedAt.IsZero() ||
		certificate.IssuedAt.Before(certificate.TimestampIssuedAt) || certificate.SignatureAlgorithm != SignatureAlgorithm ||
		certificate.HashAlgorithm != HashAlgorithm {
		return ErrVerificationCertificateBinding
	}
	for _, outcome := range certificate.Outcomes {
		if strings.TrimSpace(outcome.RuleID) == "" || !outcome.Status.IsValid() {
			return ErrVerificationCertificateBinding
		}
	}
	if requireValue && certificate.Value == "" {
		return ErrVerificationCertificateRequired
	}
	return nil
}

func copyVerificationCertificate(certificate VerificationCertificate) VerificationCertificate {
	certificate.Outcomes = copyRecalculatedOutcomes(certificate.Outcomes)
	return certificate
}

func copyRecalculatedOutcomes(source []RecalculatedOutcome) []RecalculatedOutcome {
	result := make([]RecalculatedOutcome, len(source))
	for index, outcome := range source {
		result[index] = outcome
		result[index].ReasonCodes = append([]evaluation.ReasonCode(nil), outcome.ReasonCodes...)
	}
	return result
}

func sameRecalculatedOutcomes(left, right []RecalculatedOutcome) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].RuleID != right[index].RuleID || left[index].Status != right[index].Status ||
			!sameReasonCodes(left[index].ReasonCodes, right[index].ReasonCodes) {
			return false
		}
	}
	return true
}
