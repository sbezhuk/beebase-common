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

// Verifier checks access tokens signed by auth-service.
type Verifier struct {
	keyfunc jwt.Keyfunc
}

// NewVerifierFromJWKSURL fetches and caches auth-service's public key from
// its JWKS endpoint (conventionally GET /.well-known/jwks.json), refreshing
// it in the background so a future key rotation on auth-service doesn't
// require restarting this service.
func NewVerifierFromJWKSURL(ctx context.Context, jwksURL string) (*Verifier, error) {
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{jwksURL})
	if err != nil {
		return nil, fmt.Errorf("authmw: build JWKS client for %s: %w", jwksURL, err)
	}
	return &Verifier{keyfunc: kf.Keyfunc}, nil
}

// NewVerifierFromPublicKey builds a Verifier directly from a known public
// key, with no network access. Intended for auth-service to verify the
// tokens it issues itself.
func NewVerifierFromPublicKey(pub ed25519.PublicKey) *Verifier {
	return &Verifier{
		keyfunc: func(*jwt.Token) (any, error) { return pub, nil },
	}
}

// Parse verifies tokenString and returns the user ID it was issued for.
func (v *Verifier) Parse(tokenString string) (uuid.UUID, error) {
	var claims jwt.RegisteredClaims

	_, err := jwt.ParseWithClaims(tokenString, &claims, v.keyfunc, jwt.WithValidMethods([]string{"EdDSA"}))
	if err != nil {
		return uuid.Nil, ErrInvalidToken
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, ErrInvalidToken
	}

	return userID, nil
}
