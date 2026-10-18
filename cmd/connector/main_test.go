package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/internal/config"
)

// TestRedactionOffByDefault: with OTA off (TRAVERSAL_CONFIG_ENABLED unset)
// and no rules file, startRedaction fetches nothing and starts with no rules,
// even with TRAVERSAL_CONFIG_KEYS set to a bundle that does not parse: the
// signing keys only matter once OTA is on.
func TestRedactionOffByDefault(t *testing.T) {
	var fetches atomic.Int32
	controller := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		fetches.Add(1)
	}))
	t.Cleanup(controller.Close)
	for name, keys := range map[string]string{"no keys": "", "unparseable keys": "not a bundle"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("TRAVERSAL_CONFIG_KEYS", keys)
			cfg := &config.Config{
				TraversalControllerURL: controller.URL,
				ConnectorID:            "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d00",
				ConfigRefreshInterval:  time.Millisecond,
			}
			redactor, err := startRedaction(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			if redactor.HasRulesForHost("api.internal") {
				t.Fatal("rules with OTA off")
			}
			time.Sleep(20 * time.Millisecond) // a refresh interval, many times over
			if n := fetches.Load(); n != 0 {
				t.Fatalf("%d config fetches with OTA off", n)
			}
		})
	}
}
