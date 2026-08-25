// Package jwks serves a public key as a JSON Web Key Set, so other services
// can fetch and verify tokens signed by its holder without ever gaining the
// ability to mint them.
package jwks

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"

	"github.com/MicahParks/jwkset"
)

// NewHandler returns an http.HandlerFunc serving pub as a JSON Web Key Set,
// conventionally mounted at GET /.well-known/jwks.json. kid identifies this
// key and must match the "kid" header on tokens signed with the matching
// private key.
func NewHandler(pub ed25519.PublicKey, kid string) (http.HandlerFunc, error) {
	store := jwkset.NewMemoryStorage()

	jwk, err := jwkset.NewJWKFromKey(pub, jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{
			KID: kid,
			ALG: jwkset.AlgEdDSA,
			USE: jwkset.UseSig,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("jwks: build JWK: %w", err)
	}

	if err := store.KeyWrite(context.Background(), jwk); err != nil {
		return nil, fmt.Errorf("jwks: write JWK: %w", err)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := store.JSONPublic(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}, nil
}
