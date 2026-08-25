package authmw_test

import (
	"context"
	"crypto/ed25519"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/sbezhuk/beebase-common/authmw"
	"github.com/sbezhuk/beebase-common/jwks"
)

func signToken(t *testing.T, priv ed25519.PrivateKey, kid string, userID uuid.UUID, ttl time.Duration) string {
	t.Helper()

	claims := jwt.RegisteredClaims{
		Subject:   userID.String(),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func TestVerifierFromPublicKey_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	userID := uuid.New()
	token := signToken(t, priv, "test-kid", userID, time.Minute)

	verifier := authmw.NewVerifierFromPublicKey(pub)

	got, err := verifier.Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got != userID {
		t.Fatalf("Parse returned %s, want %s", got, userID)
	}
}

func TestVerifierFromPublicKey_RejectsWrongKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}

	token := signToken(t, priv, "test-kid", uuid.New(), time.Minute)

	verifier := authmw.NewVerifierFromPublicKey(otherPub)
	if _, err := verifier.Parse(token); err == nil {
		t.Fatal("Parse accepted a token signed by a different key")
	}
}

func TestVerifierFromPublicKey_RejectsExpiredToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	token := signToken(t, priv, "test-kid", uuid.New(), -time.Minute)

	verifier := authmw.NewVerifierFromPublicKey(pub)
	if _, err := verifier.Parse(token); err == nil {
		t.Fatal("Parse accepted an expired token")
	}
}

// TestVerifierFromJWKSURL_EndToEnd proves the full loop a real deployment
// relies on: sign with a private key, serve the public key as a JWKS
// document over HTTP, fetch and verify it from a completely independent
// Verifier instance, the way a different service would.
func TestVerifierFromJWKSURL_EndToEnd(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	handler, err := jwks.NewHandler(pub, "test-kid")
	if err != nil {
		t.Fatalf("jwks.NewHandler: %v", err)
	}

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	verifier, err := authmw.NewVerifierFromJWKSURL(ctx, srv.URL)
	if err != nil {
		t.Fatalf("NewVerifierFromJWKSURL: %v", err)
	}

	userID := uuid.New()
	token := signToken(t, priv, "test-kid", userID, time.Minute)

	got, err := verifier.Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got != userID {
		t.Fatalf("Parse returned %s, want %s", got, userID)
	}
}
