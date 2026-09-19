package sessionstore_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/sbezhuk/beebase-common/sessionstore"
)

// newTestStore connects to a real Redis, skipping the test entirely when
// TEST_REDIS_ADDR isn't set - this package's CI (see .github/workflows/ci.yml)
// runs plain `go test ./...` with no Redis service available, and these
// tests exist to prove the real Lua-script atomicity a fake/in-memory
// store never could, so they can't be faked out; they simply don't run
// without real infrastructure to run against.
func newTestStore(t *testing.T) (*sessionstore.Store, *redis.Client) {
	t.Helper()

	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR not set; skipping sessionstore Redis test")
	}

	client, err := sessionstore.NewRedisClient(context.Background(), addr)
	if err != nil {
		t.Fatalf("connect to redis at %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return sessionstore.NewStore(client), client
}

func TestDeactivateAndReturnPrevious_ActiveSession_ReturnsAndClearsIt(t *testing.T) {
	store, _ := newTestStore(t)
	userID := uuid.New()
	sessionID := uuid.New()

	if err := store.Activate(context.Background(), userID, sessionID, time.Minute); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	previous, hadPrevious, err := store.DeactivateAndReturnPrevious(context.Background(), userID)
	if err != nil {
		t.Fatalf("DeactivateAndReturnPrevious: %v", err)
	}
	if !hadPrevious {
		t.Fatal("hadPrevious = false, want true")
	}
	if previous != sessionID {
		t.Fatalf("previous = %v, want %v", previous, sessionID)
	}

	if active, err := store.IsActive(context.Background(), userID, sessionID); err != nil {
		t.Fatalf("IsActive: %v", err)
	} else if active {
		t.Error("session still reports active after DeactivateAndReturnPrevious")
	}
}

func TestDeactivateAndReturnPrevious_NoActiveSession_SafeNoop(t *testing.T) {
	store, _ := newTestStore(t)
	userID := uuid.New()

	previous, hadPrevious, err := store.DeactivateAndReturnPrevious(context.Background(), userID)
	if err != nil {
		t.Fatalf("DeactivateAndReturnPrevious: got error %v, want nil (no active session is a well-defined, not an error, outcome)", err)
	}
	if hadPrevious {
		t.Fatalf("hadPrevious = true (previous=%v), want false - nothing was ever activated for this user", previous)
	}
}

func TestDeactivateAndReturnPrevious_RepeatedCall_SecondReportsNoPrevious(t *testing.T) {
	store, _ := newTestStore(t)
	userID := uuid.New()
	sessionID := uuid.New()
	if err := store.Activate(context.Background(), userID, sessionID, time.Minute); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	if _, hadPrevious, err := store.DeactivateAndReturnPrevious(context.Background(), userID); err != nil || !hadPrevious {
		t.Fatalf("first call: hadPrevious=%v err=%v, want true, nil", hadPrevious, err)
	}
	if _, hadPrevious, err := store.DeactivateAndReturnPrevious(context.Background(), userID); err != nil || hadPrevious {
		t.Fatalf("second call: hadPrevious=%v err=%v, want false, nil (repeated deactivation must be idempotent)", hadPrevious, err)
	}
}

// TestDeactivateAndReturnPrevious_MalformedValue_ReturnsError writes a
// value directly into the active-session key that Activate would never
// produce (Activate only ever stores uuid.String()), simulating data
// corruption or a key collision, and confirms this is reported as an
// error - not silently treated as "no active session", which would let a
// caller wrongly assume there was nothing to invalidate or clean up.
func TestDeactivateAndReturnPrevious_MalformedValue_ReturnsError(t *testing.T) {
	store, client := newTestStore(t)
	userID := uuid.New()

	if err := client.Set(context.Background(), "session:active:"+userID.String(), "not-a-uuid", time.Minute).Err(); err != nil {
		t.Fatalf("seed malformed value: %v", err)
	}

	_, hadPrevious, err := store.DeactivateAndReturnPrevious(context.Background(), userID)
	if err == nil {
		t.Fatal("DeactivateAndReturnPrevious with a malformed stored value: want an error, got nil")
	}
	if hadPrevious {
		t.Error("hadPrevious = true alongside an error - the two must not both be reported as success-shaped")
	}

	// The corrupted marker is still cleared, even though it's reported as
	// an error - lingering malformed data helps no one, and the caller
	// already knows (via the error) not to trust "nothing was active".
	if active, err := client.Exists(context.Background(), "session:active:"+userID.String()).Result(); err != nil {
		t.Fatalf("Exists: %v", err)
	} else if active != 0 {
		t.Error("malformed active-session key was not cleared")
	}
}

// TestDeactivateAndReturnPrevious_RedisFailure_PropagatesError confirms a
// genuine Redis-level failure (here, a client pointed at a port nothing
// is listening on) surfaces as an error rather than being swallowed into
// a false "no active session".
func TestDeactivateAndReturnPrevious_RedisFailure_PropagatesError(t *testing.T) {
	if os.Getenv("TEST_REDIS_ADDR") == "" {
		t.Skip("TEST_REDIS_ADDR not set; skipping sessionstore Redis test")
	}

	// Port 1 is reserved (tcpmux) and nothing binds to it in any test
	// environment - Eval must fail fast with a connection error rather
	// than hang or silently succeed. MaxRetries disabled so the test
	// isn't slowed down by the client's default retry/backoff behavior.
	badClient := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond, MaxRetries: -1})
	defer func() { _ = badClient.Close() }()
	store := sessionstore.NewStore(badClient)

	_, hadPrevious, err := store.DeactivateAndReturnPrevious(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("DeactivateAndReturnPrevious against an unreachable Redis: want an error, got nil")
	}
	if hadPrevious {
		t.Error("hadPrevious = true alongside a connection error")
	}
}

// TestDeactivateAndReturnPrevious_GenerationUntouched confirms this
// operation, unlike ActivateAndReturnPreviousWithGeneration, never reads
// or writes the session-generation counter: a generation obtained before
// deactivating must still be exactly one less than the next one obtained
// after re-activating, proving nothing in between reset or bumped it.
func TestDeactivateAndReturnPrevious_GenerationUntouched(t *testing.T) {
	store, _ := newTestStore(t)
	userID := uuid.New()

	_, _, firstGeneration, err := store.ActivateAndReturnPreviousWithGeneration(context.Background(), userID, uuid.New(), time.Minute)
	if err != nil {
		t.Fatalf("ActivateAndReturnPreviousWithGeneration (first): %v", err)
	}

	if _, hadPrevious, err := store.DeactivateAndReturnPrevious(context.Background(), userID); err != nil || !hadPrevious {
		t.Fatalf("DeactivateAndReturnPrevious: hadPrevious=%v err=%v, want true, nil", hadPrevious, err)
	}

	_, _, secondGeneration, err := store.ActivateAndReturnPreviousWithGeneration(context.Background(), userID, uuid.New(), time.Minute)
	if err != nil {
		t.Fatalf("ActivateAndReturnPreviousWithGeneration (second): %v", err)
	}

	if secondGeneration != firstGeneration+1 {
		t.Errorf("generation after DeactivateAndReturnPrevious = %d, want %d (exactly one more than before - DeactivateAndReturnPrevious must not touch the generation counter)", secondGeneration, firstGeneration+1)
	}
}

// TestDeactivateAndReturnPrevious_ConcurrentCallers_NoSessionReportedTwice
// hammers the same user's key with genuinely concurrent
// DeactivateAndReturnPrevious calls and checks the one invariant that
// must hold regardless of scheduling: a session id is never reported as
// "previous" by more than one caller. A non-atomic "GET then DEL" pair of
// round trips could let two concurrent callers both read the same value
// before either deletes it, double-reporting the same session.
func TestDeactivateAndReturnPrevious_ConcurrentCallers_NoSessionReportedTwice(t *testing.T) {
	store, _ := newTestStore(t)
	userID := uuid.New()
	const n = 20

	for i := 0; i < n; i++ {
		if err := store.Activate(context.Background(), userID, uuid.New(), time.Minute); err != nil {
			t.Fatalf("Activate: %v", err)
		}
	}

	var mu sync.Mutex
	seen := map[uuid.UUID]int{}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			previous, hadPrevious, err := store.DeactivateAndReturnPrevious(context.Background(), userID)
			if err != nil {
				t.Errorf("DeactivateAndReturnPrevious: %v", err)
				return
			}
			if !hadPrevious {
				return
			}
			mu.Lock()
			seen[previous]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	for id, count := range seen {
		if count > 1 {
			t.Errorf("session %v was reported as the 'previous' session by %d concurrent callers, want at most 1", id, count)
		}
	}
}

// TestDeactivateAndReturnPrevious_ConcurrentWithActivate_NeverReportsStaleSession
// races a burst of concurrent Activate calls (simulating logins/refreshes
// on other devices) against a single DeactivateAndReturnPrevious call,
// and checks the invariant consistent with the rest of sessionstore's
// "last write wins" semantics: whatever DeactivateAndReturnPrevious
// reports (if anything) must be one of the session ids actually
// activated, and after it returns, the key holds either nothing or a
// session id that isn't the one just reported - it can never echo back a
// session id while that same id remains the active marker (which would
// mean it reported something it didn't actually clear).
func TestDeactivateAndReturnPrevious_ConcurrentWithActivate_NeverReportsStaleSession(t *testing.T) {
	store, _ := newTestStore(t)
	userID := uuid.New()
	const n = 20

	activated := make([]uuid.UUID, n)
	for i := range activated {
		activated[i] = uuid.New()
	}
	isActivated := make(map[uuid.UUID]bool, n)
	for _, id := range activated {
		isActivated[id] = true
	}

	var wg sync.WaitGroup
	var reported uuid.UUID
	var hadPrevious bool
	var deactivateErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		reported, hadPrevious, deactivateErr = store.DeactivateAndReturnPrevious(context.Background(), userID)
	}()
	for _, id := range activated {
		wg.Add(1)
		go func(id uuid.UUID) {
			defer wg.Done()
			if err := store.Activate(context.Background(), userID, id, time.Minute); err != nil {
				t.Errorf("Activate: %v", err)
			}
		}(id)
	}
	wg.Wait()

	if deactivateErr != nil {
		t.Fatalf("DeactivateAndReturnPrevious: %v", deactivateErr)
	}
	if hadPrevious && !isActivated[reported] {
		t.Fatalf("DeactivateAndReturnPrevious reported %v, which was never one of the sessions activated for this user", reported)
	}
	if hadPrevious {
		if active, err := store.IsActive(context.Background(), userID, reported); err != nil {
			t.Fatalf("IsActive: %v", err)
		} else if active {
			t.Errorf("session %v still reports active after being reported as the one deactivated", reported)
		}
	}
}
