package policy

import (
	"errors"
	"strings"
	"time"
)

type LifecycleStatus string

const (
	LifecycleActive    LifecycleStatus = "ACTIVE"
	LifecycleSuspended LifecycleStatus = "SUSPENDED"
	LifecycleRetired   LifecycleStatus = "RETIRED"
)

var (
	ErrApprovalRequired         = errors.New("policy: approval record is required")
	ErrApproverRequired         = errors.New("policy: approver is required")
	ErrApprovedAtRequired       = errors.New("policy: approval time is required")
	ErrActivationTimeRequired   = errors.New("policy: activation time is required")
	ErrApprovalIdentityMismatch = errors.New("policy: approval identity does not match policy")
	ErrApprovalAfterActivation  = errors.New("policy: approval must precede activation")
	ErrInvalidLifecycleChange   = errors.New("policy: invalid lifecycle transition")
)

type ApprovalRecord struct {
	PolicyID   string    `json:"policy_id"`
	Version    string    `json:"version"`
	PolicyHash string    `json:"policy_hash"`
	ApprovedBy string    `json:"approved_by"`
	ApprovedAt time.Time `json:"approved_at"`
}

type ActivatedVersion struct {
	verified  *VerifiedVersion
	approval  ApprovalRecord
	activated time.Time
}

func Activate(verified *VerifiedVersion, approval ApprovalRecord, activatedAt time.Time) (*ActivatedVersion, error) {
	if verified == nil || verified.Version() == nil {
		return nil, ErrPolicyNotFound
	}
	approval.PolicyID = strings.TrimSpace(approval.PolicyID)
	approval.Version = strings.TrimSpace(approval.Version)
	approval.PolicyHash = strings.TrimSpace(approval.PolicyHash)
	approval.ApprovedBy = strings.TrimSpace(approval.ApprovedBy)
	approval.ApprovedAt = approval.ApprovedAt.UTC()
	activatedAt = activatedAt.UTC()
	snapshot := verified.Version().Snapshot()
	switch {
	case approval.ApprovedBy == "":
		return nil, ErrApproverRequired
	case approval.ApprovedAt.IsZero():
		return nil, ErrApprovedAtRequired
	case activatedAt.IsZero():
		return nil, ErrActivationTimeRequired
	case approval.PolicyID != snapshot.PolicyID || approval.Version != snapshot.Version || approval.PolicyHash != snapshot.Hash:
		return nil, ErrApprovalIdentityMismatch
	case approval.ApprovedAt.After(activatedAt):
		return nil, ErrApprovalAfterActivation
	}
	return &ActivatedVersion{verified: verified, approval: approval, activated: activatedAt}, nil
}

func (v *ActivatedVersion) VerifiedVersion() *VerifiedVersion {
	if v == nil {
		return nil
	}
	return v.verified
}

func (v *ActivatedVersion) Approval() ApprovalRecord {
	if v == nil {
		return ApprovalRecord{}
	}
	return v.approval
}

func (v *ActivatedVersion) ActivatedAt() time.Time {
	if v == nil {
		return time.Time{}
	}
	return v.activated
}
