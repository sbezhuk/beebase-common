package authmw

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AccessClaims is the JWT claim set auth-service signs into every access
// token and every verifier parses it back into. SessionID ties the token
// to the one session it was issued for, so a Verifier backed by a
// SessionChecker can reject it the instant that session is superseded,
// without waiting for the token's own expiry.
type AccessClaims struct {
	jwt.RegisteredClaims
	SessionID         uuid.UUID `json:"sid"`
	SessionGeneration int64     `json:"sg"`
}
