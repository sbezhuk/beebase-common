// Package authmw verifies BeeBase access tokens and provides the HTTP
// middleware that guards protected routes with them.
//
// Every access token is an EdDSA-signed JWT. auth-service holds the only
// private key and is the only service that can mint tokens; every other
// service verifies them against auth-service's public key, either fetched
// live from its JWKS endpoint (NewVerifierFromJWKSURL) or, for auth-service
// itself, held directly in memory (NewVerifierFromPublicKey) so it never
// needs a network round trip to check its own tokens.
package authmw

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ErrInvalidToken is returned for any access token that fails to parse,
// fails signature verification, or has expired. Callers don't need (and
// shouldn't act on) the distinction between those cases.
var ErrInvalidToken = errors.New("invalid access token")

// SessionChecker reports whether sessionID is still the active session for
// userID. Satisfied by *sessionstore.Store; kept as a narrow interface
// here so authmw doesn't need to depend on Redis directly.
type SessionChecker interface {
	IsActive(ctx context.Context, userID, sessionID uuid.UUID) (bool, error)
}

// Verifier checks access tokens signed by auth-service.
type Verifier struct {
	keyfunc  jwt.Keyfunc
	sessions SessionChecker
}

// NewVerifierFromJWKSURL fetches and caches auth-service's public key from
// its JWKS endpoint (conventionally GET /.well-known/jwks.json), refreshing
// it in the background so a future key rotation on auth-service doesn't
// require restarting this service. sessions is consulted on every Parse
// call so a token superseded by a newer session is rejected immediately,
// rather than staying valid until its own expiry.
func NewVerifierFromJWKSURL(ctx context.Context, jwksURL string, sessions SessionChecker) (*Verifier, error) {
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{jwksURL})
	if err != nil {
		return nil, fmt.Errorf("authmw: build JWKS client for %s: %w", jwksURL, err)
	}
	return &Verifier{keyfunc: kf.Keyfunc, sessions: sessions}, nil
}

// NewVerifierFromPublicKey builds a Verifier directly from a known public
// key, with no network access. Intended for auth-service to verify the
// tokens it issues itself. See NewVerifierFromJWKSURL for sessions.
func NewVerifierFromPublicKey(pub ed25519.PublicKey, sessions SessionChecker) *Verifier {
	return &Verifier{
		keyfunc:  func(*jwt.Token) (any, error) { return pub, nil },
		sessions: sessions,
	}
}

// Parse verifies tokenString - signature, expiry, and that the session it
// was issued for is still the user's active one - and returns the user ID
// it was issued for.
func (v *Verifier) Parse(ctx context.Context, tokenString string) (uuid.UUID, error) {
	userID, _, err := v.ParseSession(ctx, tokenString)
	return userID, err
}

// ParseSession verifies tokenString and returns both its user and session IDs.
func (v *Verifier) ParseSession(ctx context.Context, tokenString string) (uuid.UUID, uuid.UUID, error) {
	userID, sessionID, _, err := v.ParseSessionWithGeneration(ctx, tokenString)
	return userID, sessionID, err
}

func (v *Verifier) ParseSessionWithGeneration(ctx context.Context, tokenString string) (uuid.UUID, uuid.UUID, int64, error) {
	var claims AccessClaims

	_, err := jwt.ParseWithClaims(tokenString, &claims, v.keyfunc, jwt.WithValidMethods([]string{"EdDSA"}))
	if err != nil {
		return uuid.Nil, uuid.Nil, 0, ErrInvalidToken
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, uuid.Nil, 0, ErrInvalidToken
	}

	active, err := v.sessions.IsActive(ctx, userID, claims.SessionID)
	if err != nil || !active {
		return uuid.Nil, uuid.Nil, 0, ErrInvalidToken
	}

	return userID, claims.SessionID, claims.SessionGeneration, nil
}
