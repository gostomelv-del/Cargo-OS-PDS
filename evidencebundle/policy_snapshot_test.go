package evidencebundle

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"cargoos/policy"
)

func policySnapshotFixture(t *testing.T) (BuildInput, policy.Snapshot) {
	t.Helper()
	input := bundleFixture(t)
	version, err := policy.NewVersion(policy.Input{
		PolicyID: "cargo-transfer", Version: "1.0.0", SchemaVersion: "policy.v1",
		EffectiveFrom: input.Trace.CreatedAt.Add(-time.Hour), RequiredRuleIDs: []string{"weight"},
		Document: json.RawMessage(`{"rules":[{"id":"weight","operator":"RANGE","max":25}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := version.Snapshot()
	input.Trace.PolicyBinding.Hash = snapshot.Hash
	return input, snapshot
}

func TestBuildWithPolicySnapshotProducesCompleteBoundBundle(t *testing.T) {
	input, snapshot := policySnapshotFixture(t)
	bundle, err := BuildWithPolicySnapshot(input, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err = Verify(bundle); err != nil {
		t.Fatal(err)
	}
	found, err := PolicySnapshot(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if found.PolicyID != snapshot.PolicyID || found.Version != snapshot.Version || found.Hash != snapshot.Hash ||
		string(found.Document) != string(snapshot.Document) {
		t.Fatal("complete Policy Snapshot identity changed")
	}
	if len(bundle.Manifest.Objects) != 3 || bundle.Manifest.Objects[2].Path != PolicySnapshotPath {
		t.Fatalf("unexpected complete bundle object layout: %#v", bundle.Manifest.Objects)
	}
}

func TestBuildWithPolicySnapshotRejectsBindingMismatch(t *testing.T) {
	input, snapshot := policySnapshotFixture(t)
	input.Trace.PolicyBinding.Hash = bundlePolicyHash
	if _, err := BuildWithPolicySnapshot(input, snapshot); !errors.Is(err, ErrPolicySnapshotMismatch) {
		t.Fatalf("expected snapshot binding rejection, got %v", err)
	}
}

func TestPolicySnapshotRejectsMissingModifiedAndNoncanonicalSnapshot(t *testing.T) {
	input, snapshot := policySnapshotFixture(t)
	referenceOnly, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = PolicySnapshot(referenceOnly); !errors.Is(err, ErrPolicySnapshotRequired) {
		t.Fatalf("expected missing snapshot rejection, got %v", err)
	}

	bundle, err := BuildWithPolicySnapshot(input, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for index := range bundle.Objects {
		if bundle.Objects[index].Path == PolicySnapshotPath {
			var modified policy.Snapshot
			if err = json.Unmarshal(bundle.Objects[index].Payload, &modified); err != nil {
				t.Fatal(err)
			}
			modified.Version = "substituted"
			bundle.Objects[index].Payload, err = json.Marshal(modified)
			if err != nil {
				t.Fatal(err)
			}
			bundle.Manifest.Objects[index] = describe(bundle.Objects[index])
			bundle.Manifest.BundleRoot = calculateRoot(bundle.Manifest)
			break
		}
	}
	if _, err = PolicySnapshot(bundle); !errors.Is(err, policy.ErrHashMismatch) {
		t.Fatalf("expected modified snapshot rejection, got %v", err)
	}

	bundle, err = BuildWithPolicySnapshot(input, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for index := range bundle.Objects {
		if bundle.Objects[index].Path == PolicySnapshotPath {
			bundle.Objects[index].Payload = append([]byte(" "), bundle.Objects[index].Payload...)
			bundle.Manifest.Objects[index] = describe(bundle.Objects[index])
			bundle.Manifest.BundleRoot = calculateRoot(bundle.Manifest)
			break
		}
	}
	if _, err = PolicySnapshot(bundle); !errors.Is(err, ErrPolicySnapshotMismatch) {
		t.Fatalf("expected noncanonical snapshot rejection, got %v", err)
	}
}

func TestPolicySnapshotSurvivesPortableArchiveRoundTrip(t *testing.T) {
	input, snapshot := policySnapshotFixture(t)
	bundle, err := BuildWithPolicySnapshot(input, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ExportArchive(bundle)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := ImportArchive(payload)
	if err != nil {
		t.Fatal(err)
	}
	found, err := PolicySnapshot(imported)
	if err != nil {
		t.Fatal(err)
	}
	if found.Hash != snapshot.Hash {
		t.Fatal("archive round trip changed Policy Snapshot hash")
	}
}
