package housekeeping_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/abandontech/abandonauth/src/api/internal/services/housekeeping"
)

func countingSweep(records string, counter *atomic.Int64) housekeeping.Sweep {
	return housekeeping.Sweep{
		Records: records,
		Forget: func(context.Context) (int64, error) {
			counter.Add(1)

			return 1, nil
		},
	}
}

func quiet() zerolog.Logger { return zerolog.New(nil).Level(zerolog.Disabled) }

func TestEverySweepRunsOnEveryPass(t *testing.T) {
	t.Parallel()

	var logins, codes atomic.Int64

	keeper, err := housekeeping.New(
		[]housekeeping.Sweep{countingSweep("logins", &logins), countingSweep("codes", &codes)},
		housekeeping.Options{Logger: quiet()},
	)
	if err != nil {
		t.Fatalf("building the keeper: %v", err)
	}

	keeper.Once(t.Context())
	keeper.Once(t.Context())

	if logins.Load() != 2 || codes.Load() != 2 {
		t.Errorf("sweeps ran %d and %d times, want 2 each", logins.Load(), codes.Load())
	}
}

// One kind of record being unremovable must not leave the others to accumulate.
func TestASweepThatFailsDoesNotStopTheRest(t *testing.T) {
	t.Parallel()

	var ran atomic.Int64

	failing := housekeeping.Sweep{
		Records: "codes",
		Forget: func(context.Context) (int64, error) {
			return 0, errors.New("the database refused")
		},
	}

	keeper, err := housekeeping.New(
		[]housekeeping.Sweep{failing, countingSweep("sessions", &ran)},
		housekeeping.Options{Logger: quiet()},
	)
	if err != nil {
		t.Fatalf("building the keeper: %v", err)
	}

	keeper.Once(t.Context())

	if ran.Load() != 1 {
		t.Errorf("the sweep after a failing one ran %d times, want 1", ran.Load())
	}
}

func TestSweepingStopsWhenTheServiceDoes(t *testing.T) {
	t.Parallel()

	var ran atomic.Int64

	keeper, err := housekeeping.New(
		[]housekeeping.Sweep{countingSweep("logins", &ran)},
		housekeeping.Options{Interval: time.Millisecond, Logger: quiet()},
	)
	if err != nil {
		t.Fatalf("building the keeper: %v", err)
	}

	ctx, stop := context.WithCancel(t.Context())

	finished := make(chan struct{})

	go func() {
		keeper.Run(ctx)
		close(finished)
	}()

	// Long enough that the ticker has fired repeatedly before the stop.
	time.Sleep(20 * time.Millisecond)
	stop()

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("sweeping did not stop when the context was cancelled")
	}

	if ran.Load() == 0 {
		t.Error("no sweep ran before the keeper was stopped")
	}

	settled := ran.Load()

	time.Sleep(20 * time.Millisecond)

	if ran.Load() != settled {
		t.Errorf("a sweep ran after the keeper stopped: %d, want %d", ran.Load(), settled)
	}
}

func TestAKeeperNeedsUsableSweeps(t *testing.T) {
	t.Parallel()

	var counter atomic.Int64

	cases := map[string][]housekeeping.Sweep{
		"nothing to sweep": {},
		"a sweep with no name": {
			{Records: "", Forget: countingSweep("x", &counter).Forget},
		},
		"a sweep with nothing to run": {
			{Records: "logins", Forget: nil},
		},
	}

	for name, sweeps := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := housekeeping.New(sweeps, housekeeping.Options{Logger: quiet()}); err == nil {
				t.Error("the keeper was built anyway")
			}
		})
	}
}
