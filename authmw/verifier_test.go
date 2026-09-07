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

// fakeSessionChecker is an in-memory stand-in for *sessionstore.Store.
// active, when non-nil, is the one session ID treated as active for
// userID; a nil map value (the zero uuid.UUID) means "no active session
// at all" for a user never registered here.
type fakeSessionChecker struct {
	active map[uuid.UUID]uuid.UUID
}

func newFakeSessionChecker() *fakeSessionChecker {
	return &fakeSessionChecker{active: map[uuid.UUID]uuid.UUID{}}
}

func (f *fakeSessionChecker) IsActive(_ context.Context, userID, sessionID uuid.UUID) (bool, error) {
	current, ok := f.active[userID]
	return ok && current == sessionID, nil
}

func signToken(t *testing.T, priv ed25519.PrivateKey, kid string, userID, sessionID uuid.UUID, ttl time.Duration) string {
	t.Helper()

	claims := authmw.AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
		},
		SessionID: sessionID,
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
	sessionID := uuid.New()
	token := signToken(t, priv, "test-kid", userID, sessionID, time.Minute)

	sessions := newFakeSessionChecker()
	sessions.active[userID] = sessionID
	verifier := authmw.NewVerifierFromPublicKey(pub, sessions)

	got, err := verifier.Parse(context.Background(), token)
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

	userID, sessionID := uuid.New(), uuid.New()
	token := signToken(t, priv, "test-kid", userID, sessionID, time.Minute)

	sessions := newFakeSessionChecker()
	sessions.active[userID] = sessionID
	verifier := authmw.NewVerifierFromPublicKey(otherPub, sessions)
	if _, err := verifier.Parse(context.Background(), token); err == nil {
		t.Fatal("Parse accepted a token signed by a different key")
	}
}

func TestVerifierFromPublicKey_RejectsExpiredToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	userID, sessionID := uuid.New(), uuid.New()
	token := signToken(t, priv, "test-kid", userID, sessionID, -time.Minute)

	sessions := newFakeSessionChecker()
	sessions.active[userID] = sessionID
	verifier := authmw.NewVerifierFromPublicKey(pub, sessions)
	if _, err := verifier.Parse(context.Background(), token); err == nil {
		t.Fatal("Parse accepted an expired token")
	}
}

// TestVerifierFromPublicKey_RejectsSupersededSession is the regression
// test for immediate access-token revocation: a token that's otherwise
// perfectly valid (right key, not expired) must still be rejected once
// its session is no longer the active one - e.g. because the user started
// a newer session elsewhere.
func TestVerifierFromPublicKey_RejectsSupersededSession(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	userID := uuid.New()
	oldSession := uuid.New()
	token := signToken(t, priv, "test-kid", userID, oldSession, time.Minute)

	sessions := newFakeSessionChecker()
	sessions.active[userID] = uuid.New() // a newer session has since taken over
	verifier := authmw.NewVerifierFromPublicKey(pub, sessions)

	if _, err := verifier.Parse(context.Background(), token); err == nil {
		t.Fatal("Parse accepted a token whose session was superseded")
	}
}

// TestVerifierFromPublicKey_RejectsWhenNoActiveSession covers logout: once
// a session is explicitly deactivated (no active session at all for the
// user), its access token must stop being accepted too.
func TestVerifierFromPublicKey_RejectsWhenNoActiveSession(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	userID, sessionID := uuid.New(), uuid.New()
	token := signToken(t, priv, "test-kid", userID, sessionID, time.Minute)

	verifier := authmw.NewVerifierFromPublicKey(pub, newFakeSessionChecker())
	if _, err := verifier.Parse(context.Background(), token); err == nil {
		t.Fatal("Parse accepted a token for a user with no active session")
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

	userID := uuid.New()
	sessionID := uuid.New()
	sessions := newFakeSessionChecker()
	sessions.active[userID] = sessionID

	verifier, err := authmw.NewVerifierFromJWKSURL(ctx, srv.URL, sessions)
	if err != nil {
		t.Fatalf("NewVerifierFromJWKSURL: %v", err)
	}

	token := signToken(t, priv, "test-kid", userID, sessionID, time.Minute)

	got, err := verifier.Parse(context.Background(), token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got != userID {
		t.Fatalf("Parse returned %s, want %s", got, userID)
	}
}
