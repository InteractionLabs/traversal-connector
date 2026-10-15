package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/InteractionLabs/traversal-connector/internal/config"
)

type tunnels struct {
	up    int
	ready bool
}

func (t tunnels) Up() int                              { return t.up }
func (t tunnels) Ready(context.Context) (bool, string) { return t.ready, "no tunnel" }

// TestReadiness: readiness is the tunnels', and the body keeps the
// active_tunnels field the API's status probe parses.
func TestReadiness(t *testing.T) {
	for _, c := range []struct {
		tunnels tunnels
		want    int
		body    string
	}{
		{tunnels{2, true}, http.StatusOK, `{"active_tunnels":2,"status":"ready"}`},
		{tunnels{0, false}, http.StatusServiceUnavailable,
			`{"active_tunnels":0,"reason":"no tunnel","status":"not ready"}`},
	} {
		w := httptest.NewRecorder()
		NewRouter(config.Config{}, c.tunnels).
			ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if w.Code != c.want || strings.TrimSpace(w.Body.String()) != c.body {
			t.Errorf("%+v: %d %s", c.tunnels, w.Code, w.Body)
		}
	}
}
