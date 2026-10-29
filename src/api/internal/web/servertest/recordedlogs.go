package servertest

import (
	"strings"
	"sync"
)

// RecordedLogs holds everything the service wrote while a test ran.
//
// The service answers requests concurrently and writes a line for each, so
// writes are serialised. Reading takes the same lock, which also means a test
// that inspects the logs while requests are still in flight sees a complete
// prefix rather than a torn one.
type RecordedLogs struct {
	mutex   sync.Mutex
	written strings.Builder
}

// Write records one log line.
func (r *RecordedLogs) Write(line []byte) (int, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	return r.written.Write(line)
}

// String is everything written so far.
func (r *RecordedLogs) String() string {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	return r.written.String()
}
