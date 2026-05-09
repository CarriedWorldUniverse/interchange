package landing

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerRootReturnsHTML(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler()(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html...", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<title>interchange</title>") {
		t.Errorf("missing lowercase title: %s", body[:200])
	}
	if !strings.Contains(body, "github.com/CarriedWorldUniverse/interchange") {
		t.Errorf("missing github link")
	}
}

func TestHandlerNonRootIs404(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler()(rec, httptest.NewRequest(http.MethodGet, "/anything", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestHandlerNonGetIs405(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler()(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET" {
		t.Errorf("Allow = %q, want GET", got)
	}
}

func TestHandlerSecurityHeadersSet(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler()(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Header().Get("Content-Security-Policy"); got == "" {
		t.Errorf("missing CSP header")
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
}

func TestHandlerLeaksNoOperationalData(t *testing.T) {
	// The page must not reveal interchange_id, version, or internal
	// endpoints beyond what /.well-known already publishes. Pin the
	// invariants by asserting absences.
	rec := httptest.NewRecorder()
	Handler()(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()
	for _, banned := range []string{
		"carried-world", "/mailbox/", "/pair/", "interchange_id",
	} {
		if strings.Contains(body, banned) {
			t.Errorf("landing page leaks %q", banned)
		}
	}
}
