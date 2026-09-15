// Package internalauth authenticates trusted backend-to-backend HTTP calls.
package internalauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

// RequireAuth accepts only the configured internal service token in a Bearer
// Authorization header. An empty configured token fails closed.
func RequireAuth(configuredToken string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if configuredToken == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			header := r.Header.Get("Authorization")
			const prefix = "Bearer "
			if !strings.HasPrefix(header, prefix) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			provided := strings.TrimPrefix(header, prefix)
			providedHash := sha256.Sum256([]byte(provided))
			configuredHash := sha256.Sum256([]byte(configuredToken))
			if provided == "" || subtle.ConstantTimeCompare(providedHash[:], configuredHash[:]) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
