package evidencebundle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"cargoos/policy"
)

// ExportSignedArchive packages a previously trusted Bundle together with its
// canonical signature envelope. Only VerifiedBundle can cross this boundary.
func ExportSignedArchive(verified *VerifiedBundle) ([]byte, error) {
	if verified == nil {
		return nil, ErrBundleSignatureRequired
	}
	bundle := verified.Bundle()
	signature := verified.Signature()
	if err := validateSignatureBinding(bundle, signature, true); err != nil {
		return nil, err
	}
	signaturePayload, err := CanonicalSignature(signature)
	if err != nil {
		return nil, err
	}
	entries, err := bundleArchiveEntries(bundle)
	if err != nil {
		return nil, err
	}
	entries = append(entries, archiveEntry{path: SignatureEntryPath, payload: signaturePayload})
	return writeArchive(entries)
}

// ImportSignedArchive verifies the complete portable archive and its embedded
// signature through the supplied Trust Store without production data access.
func ImportSignedArchive(
	ctx context.Context,
	payload []byte,
	trustStore policy.TrustStore,
	verifiedAt time.Time,
) (*VerifiedBundle, error) {
	entries, err := readArchive(payload)
	if err != nil {
		return nil, err
	}
	signaturePayload, exists := entries[SignatureEntryPath]
	if !exists {
		return nil, fmt.Errorf("%w: missing %s", ErrBundleSignatureRequired, SignatureEntryPath)
	}
	delete(entries, SignatureEntryPath)

	var signature Signature
	if err = json.Unmarshal(signaturePayload, &signature); err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrArchiveInvalid, err)
	}
	canonical, err := CanonicalSignature(signature)
	if err != nil || !bytes.Equal(canonical, signaturePayload) {
		return nil, fmt.Errorf("%w: signature is not canonical", ErrArchiveInvalid)
	}
	bundle, err := bundleFromArchiveEntries(entries)
	if err != nil {
		return nil, err
	}
	return VerifySignature(ctx, bundle, signature, trustStore, verifiedAt)
}
