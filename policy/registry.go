package policy

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrVersionConflict  = errors.New("policy: identifier and version already contain different policy")
	ErrEffectiveOverlap = errors.New("policy: effective periods overlap")
	ErrPolicyNotFound   = errors.New("policy: no effective version found")
	ErrAmbiguousPolicy  = errors.New("policy: multiple effective versions found")
)

type Registry struct {
	mu       sync.RWMutex
	versions map[string]map[string]Snapshot
}

func NewRegistry() *Registry {
	return &Registry{versions: make(map[string]map[string]Snapshot)}
}

func (r *Registry) Add(_ context.Context, verified *VerifiedVersion) error {
	if verified == nil || verified.Version() == nil {
		return ErrPolicyNotFound
	}
	snapshot := verified.Version().Snapshot()
	r.mu.Lock()
	defer r.mu.Unlock()
	byVersion := r.versions[snapshot.PolicyID]
	if byVersion == nil {
		byVersion = make(map[string]Snapshot)
		r.versions[snapshot.PolicyID] = byVersion
	}
	if existing, found := byVersion[snapshot.Version]; found {
		if existing.Hash == snapshot.Hash {
			return nil
		}
		return ErrVersionConflict
	}
	for _, existing := range byVersion {
		if effectivePeriodsOverlap(existing, snapshot) {
			return ErrEffectiveOverlap
		}
	}
	byVersion[snapshot.Version] = copySnapshot(snapshot)
	return nil
}

func (r *Registry) Resolve(_ context.Context, policyID string, at time.Time) (*Version, error) {
	r.mu.RLock()
	byVersion := r.versions[policyID]
	matches := make([]Snapshot, 0, 1)
	for _, snapshot := range byVersion {
		if effectiveAt(snapshot, at) {
			matches = append(matches, copySnapshot(snapshot))
		}
	}
	r.mu.RUnlock()
	if len(matches) == 0 {
		return nil, ErrPolicyNotFound
	}
	if len(matches) > 1 {
		return nil, ErrAmbiguousPolicy
	}
	return Rehydrate(matches[0])
}

func effectiveAt(snapshot Snapshot, at time.Time) bool {
	at = at.UTC()
	return !at.IsZero() && !at.Before(snapshot.EffectiveFrom) && (snapshot.EffectiveUntil == nil || at.Before(*snapshot.EffectiveUntil))
}

func effectivePeriodsOverlap(left, right Snapshot) bool {
	return (left.EffectiveUntil == nil || right.EffectiveFrom.Before(*left.EffectiveUntil)) &&
		(right.EffectiveUntil == nil || left.EffectiveFrom.Before(*right.EffectiveUntil))
}
