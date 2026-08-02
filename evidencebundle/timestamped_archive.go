package evidencebundle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"cargoos/policy"
)

func ExportTimestampedArchive(timestamped *TimestampedBundle) ([]byte, error) {
	if timestamped == nil || timestamped.verified == nil {
		return nil, ErrBundleTimestampRequired
	}
	entries, err := bundleArchiveEntries(timestamped.verified.bundle)
	if err != nil {
		return nil, err
	}
	signaturePayload, err := CanonicalSignature(timestamped.verified.signature)
	if err != nil {
		return nil, err
	}
	timestampPayload, err := CanonicalTimestamp(timestamped.timestamp)
	if err != nil {
		return nil, err
	}
	entries = append(entries,
		archiveEntry{path: SignatureEntryPath, payload: signaturePayload},
		archiveEntry{path: TimestampEntryPath, payload: timestampPayload},
	)
	return writeArchive(entries)
}

func ImportTimestampedArchive(ctx context.Context, payload []byte, bundleTrustStore, timestampTrustStore policy.TrustStore, verifiedAt time.Time) (*TimestampedBundle, error) {
	entries, err := readArchive(payload)
	if err != nil {
		return nil, err
	}
	timestampPayload, exists := entries[TimestampEntryPath]
	if !exists {
		return nil, fmt.Errorf("%w: missing %s", ErrBundleTimestampRequired, TimestampEntryPath)
	}
	delete(entries, TimestampEntryPath)
	var timestamp TrustedTimestamp
	if err = json.Unmarshal(timestampPayload, &timestamp); err != nil {
		return nil, fmt.Errorf("%w: timestamp: %v", ErrArchiveInvalid, err)
	}
	canonical, err := CanonicalTimestamp(timestamp)
	if err != nil || !bytes.Equal(canonical, timestampPayload) {
		return nil, fmt.Errorf("%w: timestamp is not canonical", ErrArchiveInvalid)
	}

	signedPayload, err := archivePayloadFromEntries(entries)
	if err != nil {
		return nil, err
	}
	verified, err := ImportSignedArchive(ctx, signedPayload, bundleTrustStore, timestamp.IssuedAt)
	if err != nil {
		return nil, err
	}
	return VerifyTrustedTimestamp(ctx, verified, timestamp, timestampTrustStore, verifiedAt)
}

func archivePayloadFromEntries(entries map[string][]byte) ([]byte, error) {
	archiveEntries := make([]archiveEntry, 0, len(entries))
	for path, payload := range entries {
		archiveEntries = append(archiveEntries, archiveEntry{path: path, payload: payload})
	}
	return writeArchive(archiveEntries)
}
