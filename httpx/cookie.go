package httpx

import (
	"net/http"
	"time"
)

// CookieOptions configures how a cookie is scoped and secured. Services
// build one from their own config so cookie behavior (domain, Secure,
// SameSite) stays consistent across every call site without hardcoding
// environment-specific flags into each handler.
type CookieOptions struct {
	Domain   string
	Secure   bool
	SameSite http.SameSite
}

// SetCookie sets an HttpOnly cookie named name to value, restricted to
// path, expiring at expiresAt.
func SetCookie(w http.ResponseWriter, name, value, path string, expiresAt time.Time, opts CookieOptions) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		Domain:   opts.Domain,
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   opts.Secure,
		SameSite: opts.SameSite,
	})
}

// ClearCookie deletes a previously set cookie by expiring it immediately.
// path and opts must match the values SetCookie was called with, since
// browsers scope cookies by name, path, and domain together.
func ClearCookie(w http.ResponseWriter, name, path string, opts CookieOptions) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		Domain:   opts.Domain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   opts.Secure,
		SameSite: opts.SameSite,
	})
}
