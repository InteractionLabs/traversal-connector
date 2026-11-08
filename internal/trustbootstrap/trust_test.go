package trustbootstrap

import (
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
)

func TestLoadOrEnrollPinsFirstDocument(t *testing.T) {
	first := testDocument(t, "first")
	second := testDocument(t, "second")
	body := first
	fetches := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches++
		_, _ = w.Write(body)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "state", "trust.json")

	got, err := LoadOrEnroll(t.Context(), server.Client(), server.URL, path)
	if err != nil || !got.Created || fetches != 1 || got.CapabilityRoots == "" || got.ConfigKeys == "" {
		t.Fatalf("initial enrollment: %+v, %v, fetches=%d", got, err, fetches)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %v", info.Mode().Perm())
	}

	body = second
	got, err = LoadOrEnroll(t.Context(), server.Client(), server.URL, path)
	var pinned Document
	if json.Unmarshal(first, &pinned) != nil {
		t.Fatal("decode first document")
	}
	if err != nil || got.Created || fetches != 1 || got.CapabilityRoots != pinned.CapabilityRoots {
		t.Fatalf("restart replaced or refetched trust: %+v, %v, fetches=%d", got, err, fetches)
	}
}

func TestLoadOrEnrollRejectsInvalidBeforePersisting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"schema_version":1,"capability_roots_pem":"bad","config_keys_pem":"bad"}`))
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "trust.json")
	if _, err := LoadOrEnroll(t.Context(), server.Client(), server.URL, path); err == nil {
		t.Fatal("invalid trust was accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("invalid trust was persisted: %v", err)
	}
}

func testDocument(t *testing.T, seed string) []byte {
	t.Helper()
	root := capabilitytest.ValidRoot(t, seed+"-root")
	key := capabilitytest.Key(seed + "-config")
	doc := Document{
		SchemaVersion:   1,
		CapabilityRoots: string(capabilitytest.RootsPEM(root)),
		ConfigKeys: string(capabilitytest.KeysPEM(map[string]*ecdsa.PublicKey{
			seed: &key.PublicKey,
		})),
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
