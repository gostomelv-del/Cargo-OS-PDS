package responsibility

import (
	"errors"
	"strings"
	"time"
)

var (
	ErrClaimLimitInvalid       = errors.New("responsibility: claim limit must be greater than zero")
	ErrWorkerIDRequired        = errors.New("responsibility: worker ID is required")
	ErrLockDurationInvalid     = errors.New("responsibility: lock duration must be greater than zero")
	ErrClaimTimeRequired       = errors.New("responsibility: claim time is required")
	ErrPublicationTimeRequired = errors.New("responsibility: publication time is required")
	ErrDeliveryConflict        = errors.New("responsibility: delivery lock conflict")
)

const MaxDeliveryClaim = 1000

type DeliveryClaim struct {
	Limit        int
	WorkerID     string
	ClaimedAt    time.Time
	LockDuration time.Duration
}

func (claim DeliveryClaim) Validate() error {
	if claim.Limit <= 0 || claim.Limit > MaxDeliveryClaim {
		return ErrClaimLimitInvalid
	}
	if strings.TrimSpace(claim.WorkerID) == "" {
		return ErrWorkerIDRequired
	}
	if claim.ClaimedAt.IsZero() {
		return ErrClaimTimeRequired
	}
	if claim.LockDuration <= 0 {
		return ErrLockDurationInvalid
	}
	return nil
}

type ClaimedTransfer struct {
	Event     TransferredEvent
	Attempts  uint32
	LockOwner string
	LockUntil time.Time
}
