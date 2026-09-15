package internalauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireAuth(t *testing.T) {
	const token = "development-internal-token"
	cases := []struct {
		name   string
		config string
		header string
		want   int
	}{
		{name: "valid", config: token, header: "Bearer " + token, want: http.StatusNoContent},
		{name: "missing", config: token, want: http.StatusUnauthorized},
		{name: "malformed", config: token, header: token, want: http.StatusUnauthorized},
		{name: "wrong", config: token, header: "Bearer wrong", want: http.StatusUnauthorized},
		{name: "empty configured token", header: "Bearer " + token, want: http.StatusUnauthorized},
		{name: "user JWT is not accepted", config: token, header: "Bearer eyJhbGciOiJFZERTQSJ9.user.jwt", want: http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := RequireAuth(tc.config)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			r := httptest.NewRequest(http.MethodGet, "/internal", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d", w.Code, tc.want)
			}
		})
	}
}

func TestRequireAuthDoesNotExposeToken(t *testing.T) {
	const token = "secret-token"
	h := RequireAuth(token)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	r := httptest.NewRequest(http.MethodGet, "/internal", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if body := w.Body.String(); body != "unauthorized\n" {
		t.Fatalf("body = %q, must not disclose authentication details", body)
	}
}
