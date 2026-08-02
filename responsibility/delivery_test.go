package responsibility

import (
	"errors"
	"testing"
	"time"
)

func TestDeliveryClaimValidation(t *testing.T) {
	valid := DeliveryClaim{
		Limit: 1, WorkerID: "publisher-1", ClaimedAt: time.Now().UTC(), LockDuration: time.Minute,
	}
	cases := []struct {
		name string
		edit func(*DeliveryClaim)
		want error
	}{
		{"limit", func(claim *DeliveryClaim) { claim.Limit = 0 }, ErrClaimLimitInvalid},
		{"maximum limit", func(claim *DeliveryClaim) { claim.Limit = MaxDeliveryClaim + 1 }, ErrClaimLimitInvalid},
		{"worker", func(claim *DeliveryClaim) { claim.WorkerID = " " }, ErrWorkerIDRequired},
		{"time", func(claim *DeliveryClaim) { claim.ClaimedAt = time.Time{} }, ErrClaimTimeRequired},
		{"duration", func(claim *DeliveryClaim) { claim.LockDuration = 0 }, ErrLockDurationInvalid},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			claim := valid
			test.edit(&claim)
			if err := claim.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("expected %v, got %v", test.want, err)
			}
		})
	}
}
