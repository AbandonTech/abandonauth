//go:build integration

package applications

import (
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/abandontech/abandonauth/src/api/internal/database/testdatabase"
	"github.com/abandontech/abandonauth/src/api/internal/services/accounts"
	"github.com/abandontech/abandonauth/src/api/internal/services/credentials"
	"github.com/abandontech/abandonauth/src/api/internal/services/oauth"
)

// recordingHasher stores credentials exactly as the service does and notes the
// cost recorded in every hash it is asked to compare against. What an attempt
// costs is stated by counting those comparisons rather than by timing one,
// which would describe the machine instead of the service.
type recordingHasher struct {
	hasher credentials.Hasher

	mutex      sync.Mutex
	comparedTo []int
}

func (r *recordingHasher) Hash(secret string) (string, error) {
	return r.hasher.Hash(secret)
}

func (r *recordingHasher) Matches(secret, hashed string) bool {
	cost, err := bcrypt.Cost([]byte(hashed))
	if err != nil {
		cost = 0
	}

	r.mutex.Lock()
	r.comparedTo = append(r.comparedTo, cost)
	r.mutex.Unlock()

	return r.hasher.Matches(secret, hashed)
}

func (r *recordingHasher) forget() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.comparedTo = nil
}

func (r *recordingHasher) recorded() []int {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	return append([]int(nil), r.comparedTo...)
}

// An application that does not exist and one whose credential is wrong are
// refused the same way, and each takes one comparison against a hash of the same
// cost, so what the service does says no more than what it answers.
func TestAnApplicationThatDoesNotExistIsCheckedLikeOneThatDoes(t *testing.T) {
	t.Parallel()

	pool := testdatabase.NewMigrated(t)

	owner, err := accounts.New(pool).Resolve(t.Context(), accounts.Identity{
		Provider: oauth.Discord,
		ID:       "1",
		Username: "the owner",
	})
	if err != nil {
		t.Fatalf("registering the owner account: %v", err)
	}

	recorder := &recordingHasher{hasher: credentials.NewInexpensiveHasher()}
	service := newApplications(pool, recorder)

	application, _, err := service.Create(t.Context(), owner.ID, "an application")
	if err != nil {
		t.Fatalf("registering an application: %v", err)
	}

	attempts := map[string]uuid.UUID{
		"a known application and the wrong credential": application.ID,
		"an application that does not exist":           uuid.New(),
	}

	for name, id := range attempts {
		t.Run(name, func(t *testing.T) {
			recorder.forget()

			if _, err := service.Authenticate(t.Context(), id, "placeholder-credential"); !errors.Is(
				err, ErrInvalidCredential,
			) {
				t.Fatalf("err = %v, want %v", err, ErrInvalidCredential)
			}

			costs := recorder.recorded()
			if len(costs) != 1 {
				t.Fatalf("the attempt made %d credential comparisons, want 1", len(costs))
			}

			if costs[0] != bcrypt.MinCost {
				t.Errorf("compared against a hash at cost %d, want %d", costs[0], bcrypt.MinCost)
			}
		})
	}
}
