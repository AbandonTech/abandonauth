// Package housekeeping removes records whose lifetime has ended.
//
// Nothing here decides whether a credential is still good. Every statement that
// reads one of these records to grant something already requires it to be
// unexpired, so a row removed by a sweep could no longer have been spent,
// redeemed or presented. This exists only so the tables holding short-lived
// records do not grow without bound.
//
// A sweep that fails is logged and the next one is still attempted: tidying up
// is never allowed to stop the service or to fail a request.
package housekeeping

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog"
)

// DefaultInterval is how often expired records are swept away. Each sweep is
// bounded, so the interval sets the rate at which a backlog drains rather than
// the size of any one delete.
const DefaultInterval = 10 * time.Minute

// Sweep is one kind of expired record and the work that removes it.
type Sweep struct {
	// Records names what is being removed, for the log.
	Records string

	// Forget removes a bounded number of expired records and reports how many.
	Forget func(context.Context) (int64, error)
}

// Keeper runs sweeps until it is told to stop.
type Keeper struct {
	sweeps   []Sweep
	interval time.Duration
	logger   zerolog.Logger
}

// Options are what the keeper needs.
type Options struct {
	// Interval is how often every sweep runs. Zero selects DefaultInterval.
	Interval time.Duration

	Logger zerolog.Logger
}

// New builds a keeper over the sweeps it is to run.
func New(sweeps []Sweep, options Options) (*Keeper, error) {
	if len(sweeps) == 0 {
		return nil, errors.New("housekeeping needs something to sweep")
	}

	for _, sweep := range sweeps {
		if sweep.Records == "" || sweep.Forget == nil {
			return nil, errors.New("a sweep needs a name and something to run")
		}
	}

	interval := options.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}

	return &Keeper{sweeps: sweeps, interval: interval, logger: options.Logger}, nil
}

// Run sweeps on the interval until the context is cancelled.
//
// The first sweep happens after one interval rather than at start-up, so a
// deployment that is restarting repeatedly does not spend each start on a
// delete instead of on serving.
func (k *Keeper) Run(ctx context.Context) {
	ticker := time.NewTicker(k.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			k.Once(ctx)
		}
	}
}

// Once runs every sweep a single time.
func (k *Keeper) Once(ctx context.Context) {
	for _, sweep := range k.sweeps {
		removed, err := sweep.Forget(ctx)
		if err != nil {
			// A sweep that could not run leaves rows to be removed next time,
			// which is why this is not fatal and not retried here.
			k.logger.Warn().Err(err).Str("records", sweep.Records).Msg("could not remove expired records")

			continue
		}

		if removed > 0 {
			k.logger.Debug().Int64("removed", removed).Str("records", sweep.Records).Msg("removed expired records")
		}
	}
}
