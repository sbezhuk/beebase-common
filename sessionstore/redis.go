// Package sessionstore tracks, per user, which session is currently the
// single active one, backed by Redis so every service (not just
// auth-service) can check it on every request. This is what lets an
// access token be rejected the moment it's superseded by a newer session,
// instead of staying valid until its own JWT expiry - a stateless JWT
// alone can't do that, since verifying one never touches a shared store.
package sessionstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// Store records and checks the single active session per user.
type Store struct {
	client *redis.Client
}

// NewRedisClient dials addr and confirms it's reachable before returning,
// so a misconfigured or unreachable Redis fails service startup rather
// than every request thereafter.
func NewRedisClient(ctx context.Context, addr string) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{Addr: addr})

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("sessionstore: connect to redis at %s: %w", addr, err)
	}

	return client, nil
}

// NewStore returns a Store backed by client.
func NewStore(client *redis.Client) *Store {
	return &Store{client: client}
}

// Activate marks sessionID as the only active session for userID,
// superseding whatever session (if any) was active before. ttl bounds how
// long the marker survives if it's never explicitly deactivated - it
// should match the session's own refresh-token TTL, so a marker never
// outlives the session it guards.
func (s *Store) Activate(ctx context.Context, userID, sessionID uuid.UUID, ttl time.Duration) error {
	if err := s.client.Set(ctx, activeSessionKey(userID), sessionID.String(), ttl).Err(); err != nil {
		return fmt.Errorf("sessionstore: activate session for user %s: %w", userID, err)
	}
	return nil
}

// ActivateAndReturnPrevious atomically replaces the active session and
// returns the session it superseded, if any.
func (s *Store) ActivateAndReturnPrevious(ctx context.Context, userID, sessionID uuid.UUID, ttl time.Duration) (uuid.UUID, bool, error) {
	previous, hadPrevious, _, err := s.ActivateAndReturnPreviousWithGeneration(ctx, userID, sessionID, ttl)
	return previous, hadPrevious, err
}

func (s *Store) ActivateAndReturnPreviousWithGeneration(ctx context.Context, userID, sessionID uuid.UUID, ttl time.Duration) (uuid.UUID, bool, int64, error) {
	const script = `local old = redis.call('GET', KEYS[1]); local generation = redis.call('INCR', KEYS[2]); redis.call('PEXPIRE', KEYS[2], ARGV[2]); redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2]); return {old or '', generation}`
	result, err := s.client.Eval(ctx, script, []string{activeSessionKey(userID), sessionGenerationKey(userID)}, sessionID.String(), ttl.Milliseconds()).Result()
	if err != nil {
		return uuid.Nil, false, 0, fmt.Errorf("sessionstore: activate session for user %s: %w", userID, err)
	}
	values, ok := result.([]any)
	if !ok || len(values) != 2 {
		return uuid.Nil, false, 0, fmt.Errorf("sessionstore: invalid activation result")
	}
	oldString, _ := values[0].(string)
	generation, ok := values[1].(int64)
	if !ok {
		return uuid.Nil, false, 0, fmt.Errorf("sessionstore: invalid session generation")
	}
	if oldString == "" {
		return uuid.Nil, false, generation, nil
	}
	previous, err := uuid.Parse(oldString)
	if err != nil {
		return uuid.Nil, false, generation, nil
	}
	return previous, true, generation, nil
}

func (s *Store) DeactivateIfCurrent(ctx context.Context, userID, sessionID uuid.UUID) (bool, error) {
	const script = `if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end`
	result, err := s.client.Eval(ctx, script, []string{activeSessionKey(userID)}, sessionID.String()).Int64()
	if err != nil {
		return false, fmt.Errorf("sessionstore: deactivate session for user %s: %w", userID, err)
	}
	return result == 1, nil
}

// IsActive reports whether sessionID is still the active session for
// userID. It returns false, with no error, once the marker has expired or
// was never set - callers should treat that the same as "not active", not
// as an error.
func (s *Store) IsActive(ctx context.Context, userID, sessionID uuid.UUID) (bool, error) {
	current, err := s.client.Get(ctx, activeSessionKey(userID)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sessionstore: check active session for user %s: %w", userID, err)
	}
	return current == sessionID.String(), nil
}

// Deactivate clears the active-session marker for userID, e.g. on logout
// or password change - both already revoke every refresh token for the
// user, so their access token(s) should stop being accepted immediately
// too, rather than staying valid until natural expiry.
func (s *Store) Deactivate(ctx context.Context, userID uuid.UUID) error {
	if err := s.client.Del(ctx, activeSessionKey(userID)).Err(); err != nil {
		return fmt.Errorf("sessionstore: deactivate session for user %s: %w", userID, err)
	}
	return nil
}

func activeSessionKey(userID uuid.UUID) string {
	return "session:active:" + userID.String()
}

func sessionGenerationKey(userID uuid.UUID) string {
	return "session:generation:" + userID.String()
}
