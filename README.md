# beebase-common

Shared Go packages used by every BeeBase microservice
([beebase-auth-service](https://github.com/sbezhuk/beebase-auth-service),
beebase-apiary-service, beebase-hive-service, beebase-inspection-service,
beebase-gateway).

- `logger` — slog setup (JSON in production, text in development)
- `httpx` — JSON response/error helpers with a consistent `{"error": {"code", "message"}}` shape
- `server` — `http.Server` wrapper with graceful shutdown
- `authmw` — verifies EdDSA-signed access tokens (fetched live from a
  service's JWKS endpoint, or held directly for the issuing service itself)
  and the `RequireAuth` HTTP middleware built on it
- `jwks` — serves a public key as a JSON Web Key Set; used only by
  auth-service, which is the only service holding a private key

## Trust model

auth-service holds the only Ed25519 private key and is the only service
that can mint access tokens. Every other service verifies tokens against
auth-service's public key (via `authmw.NewVerifierFromJWKSURL`, pointed at
auth-service's `/.well-known/jwks.json`) without ever being able to forge
one — the asymmetric-signing equivalent of "read-only" for tokens.
