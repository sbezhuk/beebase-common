package authmw

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/sbezhuk/beebase-common/httpx"
)

type contextKey int

const (
	userIDContextKey contextKey = iota
	sessionIDContextKey
	sessionGenerationContextKey
)

// Error codes for authentication failures. Kept distinct so a client can
// tell "you were never logged in" (CodeMissingAuthorization) apart from
// "your session ended" (CodeInvalidAccessToken) and localize accordingly.
const (
	CodeMissingAuthorization = "missing_authorization"
	CodeInvalidAccessToken   = "invalid_access_token"
)

// AccessTokenParser verifies an access token string and returns the user
// ID it was issued for. Satisfied by *Verifier.
type AccessTokenParser interface {
	Parse(ctx context.Context, token string) (uuid.UUID, error)
}

// SessionAccessTokenParser is implemented by verifiers that expose the
// session identity carried by an otherwise valid access token. It is kept
// optional so existing middleware consumers remain source-compatible.
type SessionAccessTokenParser interface {
	AccessTokenParser
	ParseSession(ctx context.Context, token string) (uuid.UUID, uuid.UUID, error)
}

type SessionGenerationAccessTokenParser interface {
	SessionAccessTokenParser
	ParseSessionWithGeneration(ctx context.Context, token string) (uuid.UUID, uuid.UUID, int64, error)
}

// RequireAuth returns middleware that rejects requests without a valid
// "Authorization: Bearer <token>" header, and otherwise makes the
// authenticated user's ID available via UserIDFromContext.
func RequireAuth(parser AccessTokenParser) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearerToken(r)
			if !ok {
				httpx.WriteError(w, http.StatusUnauthorized, CodeMissingAuthorization, "missing or invalid authorization header")
				return
			}

			var userID uuid.UUID
			var sessionID uuid.UUID
			var sessionGeneration int64
			var err error
			if sessionParser, ok := parser.(SessionGenerationAccessTokenParser); ok {
				userID, sessionID, sessionGeneration, err = sessionParser.ParseSessionWithGeneration(r.Context(), token)
			} else if sessionParser, ok := parser.(SessionAccessTokenParser); ok {
				userID, sessionID, err = sessionParser.ParseSession(r.Context(), token)
			} else {
				userID, err = parser.Parse(r.Context(), token)
			}
			if err != nil {
				httpx.WriteError(w, http.StatusUnauthorized, CodeInvalidAccessToken, "invalid or expired access token")
				return
			}

			ctx := context.WithValue(r.Context(), userIDContextKey, userID)
			if sessionID != uuid.Nil {
				ctx = context.WithValue(ctx, sessionIDContextKey, sessionID)
				ctx = context.WithValue(ctx, sessionGenerationContextKey, sessionGeneration)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func SessionGenerationFromContext(ctx context.Context) (int64, bool) {
	generation, ok := ctx.Value(sessionGenerationContextKey).(int64)
	return generation, ok
}

// SessionIDFromContext returns the session ID stored by RequireAuth.
func SessionIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(sessionIDContextKey).(uuid.UUID)
	return id, ok
}

// UserIDFromContext returns the user ID stored by RequireAuth, if any.
func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDContextKey).(uuid.UUID)
	return id, ok
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "

	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}

	token := strings.TrimPrefix(header, prefix)
	if token == "" {
		return "", false
	}

	return token, true
}
