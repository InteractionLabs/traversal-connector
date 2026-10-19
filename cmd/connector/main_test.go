package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
	"github.com/InteractionLabs/traversal-connector/connector-lib/signedconfig"
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

// TestRedactionRequiresSignatureWithKeys: with OTA on, startRedaction makes
// the loader require Traversal's signature for this connector exactly when
// TRAVERSAL_CONFIG_KEYS is set (base64, as the chart renders it): an unsigned
// config, or one signed for another connector or by another key, does not
// start, and one signed for this connector does. Without keys, an unsigned
// config starts.
func TestRedactionRequiresSignatureWithKeys(t *testing.T) {
	const (
		self    = "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d00"
		sibling = "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d01"
		doc     = "schema_version = 1\n[redaction]\n[[redaction.rules]]\nname = \"t\"\n" +
			"type = \"regex\"\npattern = 'secret'\nhosts = ['api\\.internal']\n"
	)
	key, other := capabilitytest.Key("config"), capabilitytest.Key("other")
	keys := base64.StdEncoding.EncodeToString(
		capabilitytest.KeysPEM(map[string]*ecdsa.PublicKey{"k": &key.PublicKey}))
	sign := func(by *ecdsa.PrivateKey, connector string) string {
		b, err := signedconfig.Sign(by, "k", connector, 1, time.Now(),
			time.Now().Add(time.Hour), []byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, c := range []struct {
		name, keys, object string
		starts             bool
	}{
		{"keys, unsigned", keys, doc, false},
		{"keys, for another connector", keys, sign(key, sibling), false},
		{"keys, by another key", keys, sign(other, self), false},
		{"keys, signed for this connector", keys, sign(key, self), true},
		{"no keys, unsigned", "", doc, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			// An http:// controller is spoken to in h2c, as in development.
			controller := httptest.NewUnstartedServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/v1/config/"+self {
						http.NotFound(w, r)
						return
					}
					_, _ = w.Write([]byte(c.object))
				}))
			controller.Config.Protocols = new(http.Protocols)
			controller.Config.Protocols.SetUnencryptedHTTP2(true)
			controller.Start()
			t.Cleanup(controller.Close)
			t.Setenv("TRAVERSAL_CONFIG_KEYS", c.keys)
			cfg := &config.Config{
				TraversalControllerURL: controller.URL,
				ConnectorID:            self,
				ConfigEnabled:          true,
				ConfigRefreshInterval:  time.Hour,
			}
			redactor, err := startRedaction(t.Context(), cfg)
			if (err == nil) != c.starts {
				t.Fatalf("startRedaction: %v, want it to start: %v", err, c.starts)
			}
			if c.starts && !redactor.HasRulesForHost("api.internal") {
				t.Fatal("started without the config's rules")
			}
		})
	}
}
