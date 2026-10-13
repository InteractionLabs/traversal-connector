package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/InteractionLabs/traversal-connector/internal/client"
	"github.com/InteractionLabs/traversal-connector/internal/config"
)

// rawTunnels is a raw pipe side that is ready or not.
type rawTunnels bool

func (r rawTunnels) Ready(context.Context) (bool, string) { return bool(r), "raw" }

// TestReadyNeedsRawTunnels: with no legacy tunnel the connector is unready,
// whatever raw pipes report.
func TestReadyNeedsRawTunnels(t *testing.T) {
	cm, err := client.NewConnectionManager(&config.Config{MaxTunnelsAllowed: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]RawTunnels{
		"raw pipes off": nil, "raw ready": rawTunnels(true), "raw unready": rawTunnels(false),
	} {
		w := httptest.NewRecorder()
		NewRouter(config.Config{}, cm, raw).
			ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
}
