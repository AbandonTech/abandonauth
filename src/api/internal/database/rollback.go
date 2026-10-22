package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// rollbackTimeout bounds the cleanup of a transaction. A request that has
// already been abandoned by its client must still give its connection back,
// and must not be able to hold it for ever while doing so.
const rollbackTimeout = 5 * time.Second

// Rollback abandons a transaction, unless it has already been committed or
// rolled back, in which case there is nothing to do and no error.
//
// The cleanup is detached from the caller's context, because the usual reason
// to be here is that the context was cancelled, and a rollback that inherits
// the cancellation never runs. It is bounded instead. A rollback that fails
// leaves the connection in a state nothing can rely on; the driver closes such
// a connection rather than returning it to the pool.
func Rollback(ctx context.Context, transaction pgx.Tx) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()

	err := transaction.Rollback(cleanup)
	if err == nil || errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}

	return fmt.Errorf("abandoning a transaction: %w", err)
}
