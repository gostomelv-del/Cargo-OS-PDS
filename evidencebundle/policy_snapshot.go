package evidencebundle

import (
	"encoding/json"
	"errors"
	"sort"

	"cargoos/policy"
)

const PolicySnapshotPath = "policy/snapshot.json"

var (
	ErrPolicySnapshotRequired = errors.New("evidencebundle: complete policy snapshot is required")
	ErrPolicySnapshotMismatch = errors.New("evidencebundle: policy snapshot does not match decision binding")
)

// BuildWithPolicySnapshot creates a Bundle whose Policy object is the complete,
// immutable Policy Version snapshot rather than a reference alone.
func BuildWithPolicySnapshot(input BuildInput, snapshot policy.Snapshot) (Bundle, error) {
	version, err := policy.Rehydrate(snapshot)
	if err != nil {
		return Bundle{}, err
	}
	snapshot = version.Snapshot()
	if input.Trace.PolicyBinding == nil ||
		snapshot.PolicyID != input.Trace.PolicyBinding.PolicyID ||
		snapshot.Version != input.Trace.PolicyBinding.Version ||
		snapshot.Hash != input.Trace.PolicyBinding.Hash {
		return Bundle{}, ErrPolicySnapshotMismatch
	}
	bundle, err := Build(input)
	if err != nil {
		return Bundle{}, err
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return Bundle{}, err
	}
	replaced := false
	for index := range bundle.Objects {
		if bundle.Objects[index].Path == "policy/reference.json" {
			bundle.Objects[index] = Object{Path: PolicySnapshotPath, MediaType: "application/json", Payload: payload}
			replaced = true
			break
		}
	}
	if !replaced {
		return Bundle{}, ErrPolicySnapshotRequired
	}
	sort.Slice(bundle.Objects, func(i, j int) bool { return bundle.Objects[i].Path < bundle.Objects[j].Path })
	bundle.Manifest.Objects = make([]ObjectDescriptor, 0, len(bundle.Objects))
	for _, object := range bundle.Objects {
		bundle.Manifest.Objects = append(bundle.Manifest.Objects, describe(object))
	}
	bundle.Manifest.BundleRoot = calculateRoot(bundle.Manifest)
	if _, err = PolicySnapshot(bundle); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

// PolicySnapshot returns a defensive copy of the complete Policy Version after
// verifying both the Bundle and the snapshot-to-manifest binding.
func PolicySnapshot(bundle Bundle) (policy.Snapshot, error) {
	if err := Verify(bundle); err != nil {
		return policy.Snapshot{}, err
	}
	var payload json.RawMessage
	for _, object := range bundle.Objects {
		if object.Path == PolicySnapshotPath {
			if payload != nil {
				return policy.Snapshot{}, ErrPolicySnapshotMismatch
			}
			payload = append(json.RawMessage(nil), object.Payload...)
		}
	}
	if payload == nil {
		return policy.Snapshot{}, ErrPolicySnapshotRequired
	}
	var snapshot policy.Snapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return policy.Snapshot{}, ErrPolicySnapshotMismatch
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil || string(canonical) != string(payload) {
		return policy.Snapshot{}, ErrPolicySnapshotMismatch
	}
	version, err := policy.Rehydrate(snapshot)
	if err != nil {
		return policy.Snapshot{}, err
	}
	snapshot = version.Snapshot()
	if snapshot.PolicyID != bundle.Manifest.Policy.PolicyID ||
		snapshot.Version != bundle.Manifest.Policy.Version ||
		snapshot.Hash != bundle.Manifest.Policy.Hash {
		return policy.Snapshot{}, ErrPolicySnapshotMismatch
	}
	return snapshot, nil
}
