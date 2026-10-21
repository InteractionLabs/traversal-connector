package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// TestRedactionSourceFallback: startRedaction uses one source, never a merge.
// OTA wins when its first fetch succeeds (an explicit rules=[] included: the
// local rules do not apply); a first fetch that fails falls back to the local
// file when one is set, and refuses to start when none is; with neither
// configured there are no rules. A key bundle that does not parse is a
// misconfiguration and refuses to start even with a file to fall back to.
func TestRedactionSourceFallback(t *testing.T) {
	const (
		self   = "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d00"
		otaDoc = "schema_version = 1\n[redaction]\n[[redaction.rules]]\nname = \"ota\"\n" +
			"type = \"regex\"\npattern = 'secret'\nhosts = ['ota\\.internal']\n"
		emptyOTA  = "schema_version = 1\n[redaction]\nrules = []\n"
		fileRules = "version = \"v1\"\n[[rules]]\nname = \"file\"\ntype = \"regex\"\n" +
			"pattern = 'secret'\nhosts = ['file\\.internal']\n"
	)
	// controller answers the connector's config path with status and body.
	controller := func(t *testing.T, status int, body string) string {
		t.Helper()
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/config/"+self {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		srv.Config.Protocols = new(http.Protocols)
		srv.Config.Protocols.SetUnencryptedHTTP2(true)
		srv.Start()
		t.Cleanup(srv.Close)
		return srv.URL
	}
	down := httptest.NewServer(http.NotFoundHandler())
	down.Close()
	for _, c := range []struct {
		name        string
		ota         bool
		status      int
		body        string
		unreachable bool
		file        bool
		keys        string
		starts      bool
		otaRules    bool
		fileRules   bool
	}{
		{name: "OTA ok, no file", ota: true, status: 200, body: otaDoc, starts: true, otaRules: true},
		{name: "OTA ok wins over the file", ota: true, status: 200, body: otaDoc, file: true,
			starts: true, otaRules: true},
		{name: "OTA's explicit empty rules win over the file", ota: true, status: 200, body: emptyOTA,
			file: true, starts: true},
		{name: "OTA unpublished falls back to the file", ota: true, status: 404, file: true,
			starts: true, fileRules: true},
		{name: "OTA unreachable falls back to the file", ota: true, unreachable: true, file: true,
			starts: true, fileRules: true},
		{name: "OTA invalid falls back to the file", ota: true, status: 200, body: "not toml [",
			file: true, starts: true, fileRules: true},
		{name: "OTA unpublished, no file: refuses", ota: true, status: 404},
		{name: "OTA unreachable, no file: refuses", ota: true, unreachable: true},
		{name: "file only", file: true, starts: true, fileRules: true},
		{name: "neither: no rules", starts: true},
		{name: "unparseable keys refuse despite a file", ota: true, status: 200, body: otaDoc,
			file: true, keys: "not a bundle"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("TRAVERSAL_CONFIG_KEYS", c.keys)
			cfg := &config.Config{
				ConnectorID:             self,
				ConfigEnabled:           c.ota,
				ConfigRefreshInterval:   time.Hour,
				RedactionReloadInterval: time.Hour,
				TraversalControllerURL:  "http://unused.invalid",
			}
			switch {
			case c.unreachable:
				cfg.TraversalControllerURL = down.URL
			case c.ota:
				cfg.TraversalControllerURL = controller(t, c.status, c.body)
			}
			if c.file {
				path := filepath.Join(t.TempDir(), "rules.toml")
				if err := os.WriteFile(path, []byte(fileRules), 0o600); err != nil {
					t.Fatal(err)
				}
				cfg.RedactionRulesFile = &path
			}
			redactor, err := startRedaction(t.Context(), cfg)
			if (err == nil) != c.starts {
				t.Fatalf("startRedaction: %v, want it to start: %v", err, c.starts)
			}
			if !c.starts {
				return
			}
			if got := redactor.HasRulesForHost("ota.internal"); got != c.otaRules {
				t.Errorf("OTA rules applied: %v, want %v", got, c.otaRules)
			}
			if got := redactor.HasRulesForHost("file.internal"); got != c.fileRules {
				t.Errorf("file rules applied: %v, want %v", got, c.fileRules)
			}
		})
	}
}
