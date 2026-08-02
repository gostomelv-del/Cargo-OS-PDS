package evidencebundle

import (
	"errors"
	"testing"
)

func TestAuditRecordUsesExistingVerifiedBundleRoot(t *testing.T) {
	bundle, err := Build(bundleFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	record, err := NewAuditRecord(bundle.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if record.BundleID != bundle.Manifest.BundleID || record.BundleRoot == ([32]byte{}) {
		t.Fatalf("unexpected Bundle audit record: %#v", record)
	}
	bundle.Manifest.Policy.Version = "tampered"
	if _, err = NewAuditRecord(bundle.Manifest); !errors.Is(err, ErrAuditRecordInvalid) {
		t.Fatalf("expected manifest/root mismatch rejection, got %v", err)
	}
}
