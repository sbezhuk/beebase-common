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
