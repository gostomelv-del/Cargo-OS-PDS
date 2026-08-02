package estimator

import (
	"context"
	"errors"

	"cargoos/responsibility"
)

var (
	ErrResultNotFound        = errors.New("estimator: result not found")
	ErrResultAlreadyRecorded = errors.New("estimator: immutable result already recorded")
)

// Repository stores one immutable estimator result for each Object/sequence.
// Replacing a previously recorded result is forbidden, including with an
// identical value, so retries cannot hide duplicate execution.
type Repository interface {
	SaveEstimatorResult(context.Context, Result) error
	FindEstimatorResult(context.Context, responsibility.PhysicalObjectID, uint64) (Result, error)
}
