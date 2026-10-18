package redact

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
	"github.com/InteractionLabs/traversal-connector/connector-lib/signedconfig"
)

const remoteRules = `schema_version = 1
[redaction]
[[redaction.rules]]
name = "token"
type = "regex"
pattern = 'secret'
replacement = "[hidden]"
`

func TestRemoteConfigValidation(t *testing.T) {
	for _, bad := range []string{
		"", "schema_version = 1", "schema_version = 2\n[redaction]\nrules=[]",
		"schema_version = true\n[redaction]\nrules=[]",
		"schema_version = 1.0\n[redaction]\nrules=[]",
		"schema_version = 1\n[redaction]", "schema_version = 1\n[redaction]\nrules=[]\ntypo=true",
		strings.Replace(remoteRules, `type = "regex"`, `type = "typo"`, 1),
		strings.Replace(remoteRules, `name = "token"`, `name = ""`, 1),
		strings.Replace(remoteRules, `pattern = 'secret'`, `pattern = ''`, 1),
		remoteRules + "\nredact_fields = [\"message\"]",
		remoteRules + "\nredact_fields = []",
		remoteRules + "\n[[redaction.rules]]\nname='token'\ntype='regex'\npattern='other'",
		strings.Repeat(" ", MaxConfigBytes+1),
	} {
		if _, err := ParseConfig([]byte(bad)); err == nil {
			t.Errorf("invalid config accepted: %.80q", bad)
		}
	}
	for _, good := range []string{remoteRules, "schema_version=1\n[redaction]\nrules=[]"} {
		if _, err := ParseConfig([]byte(good)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRemoteLoaderLifecycle(t *testing.T) {
	status, body, etag := http.StatusOK, remoteRules, `"good"`
	var receivedETag string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %s", r.Method)
		}
		receivedETag = r.Header.Get("If-None-Match")
		if etag != "" {
			w.Header().Set("ETag", etag)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	redactor := NewRedactor()
	loader, err := NewRemoteLoader(server.Client(), server.URL, redactor, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err = loader.LoadInitial(ctx); err != nil {
		t.Fatal(err)
	}
	accepted := redactor.rules.Load()
	if got := string(applyBytes(redactor, "", []byte("secret"))); got != "[hidden]" {
		t.Fatalf("created config not applied: %s", got)
	}
	for _, statusCode := range []int{304, 200} {
		status = statusCode
		if err = loader.refresh(ctx); err != nil || receivedETag != `"good"` {
			t.Fatalf("conditional refresh: %v, ETag=%s", err, receivedETag)
		}
		if redactor.rules.Load() != accepted {
			t.Fatal("unchanged config recompiled")
		}
	}
	lastSuccess := loader.status.Load().lastSuccess
	failures := []struct {
		status int
		body   string
	}{
		{404, ""}, {403, ""}, {500, ""}, {302, ""},
		{200, "not toml ["},
		{200, strings.Replace(remoteRules, "'secret'", "'['", 1)},
		{200, strings.Replace(remoteRules, `"regex"`, `"unsupported"`, 1)},
		{200, strings.Repeat("x", MaxConfigBytes+1)},
	}
	for _, failure := range failures {
		status, body, etag = failure.status, failure.body, `"bad"`
		for range 4 { // repeated failures must never exit or clear rules
			if err = loader.refresh(ctx); err == nil {
				t.Fatalf("accepted failure: %d", status)
			}
		}
		if redactor.rules.Load() != accepted || loader.etag != `"good"` {
			t.Fatal("failure advanced the accepted version or changed rules")
		}
		if loader.status.Load().lastSuccess != lastSuccess {
			t.Fatal("failure reset config staleness")
		}
	}
	status, body, etag = 200, strings.Replace(remoteRules, "[hidden]", "[updated]", 1), `"v2"`
	if err = loader.refresh(ctx); err != nil || loader.etag != etag {
		t.Fatalf("recovery failed: %v", err)
	}
	if receivedETag != `"good"` {
		t.Fatal("bad version was sent in If-None-Match")
	}
	status, body, etag = 200, "schema_version=1\n[redaction]\nrules=[]", `"empty"`
	if err = loader.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if redactor.HasRulesForHost("example.com") || loader.status.Load().rules != 0 {
		t.Fatal("explicit empty rules did not disable redaction")
	}
}

func TestRemoteInitialFailures(t *testing.T) {
	for _, failure := range []struct {
		status int
		body   string
	}{
		{http.StatusNotModified, ""},
		{401, ""}, {403, ""}, {404, ""}, {500, ""},
		{200, ""},
		{200, "not toml ["},
		{200, strings.Replace(remoteRules, "'secret'", "'['", 1)},
		{200, strings.Repeat("x", MaxConfigBytes+1)},
	} {
		t.Run(fmt.Sprint(failure.status), func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("ETag", `"rejected"`)
					w.WriteHeader(failure.status)
					_, _ = w.Write([]byte(failure.body))
				}),
			)
			defer server.Close()
			loader, err := NewRemoteLoader(server.Client(), server.URL, NewRedactor(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if err = loader.LoadInitial(context.Background()); err == nil {
				t.Fatal("startup proceeded without confirmed config state")
			}
			if loader.loaded || loader.etag != "" || !loader.status.Load().lastSuccess.IsZero() {
				t.Fatal("failed startup accepted a version or recorded a successful fetch")
			}
		})
	}
}

func TestRemoteRestartRequiresConfig(t *testing.T) {
	var missing atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if missing.Load() {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(remoteRules))
	}))
	defer server.Close()
	redactor := NewRedactor()
	loader, err := NewRemoteLoader(server.Client(), server.URL, redactor, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err = loader.LoadInitial(ctx); err != nil {
		t.Fatal(err)
	}
	missing.Store(true)
	if err = loader.refresh(ctx); err == nil {
		t.Fatal("missing config was not reported as a runtime failure")
	}
	if got := string(applyBytes(redactor, "", []byte("secret"))); got != "[hidden]" {
		t.Fatalf("runtime 404 discarded last-known-good rules: %s", got)
	}
	// A new process has no in-memory last-known-good document.
	restarted, err := NewRemoteLoader(server.Client(), server.URL, NewRedactor(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.LoadInitial(ctx); err == nil {
		t.Fatal("restart proceeded without a config document")
	}
}

func TestRemoteRedirectAndCancellation(t *testing.T) {
	otherCalled := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		otherCalled = true
		_, _ = w.Write([]byte(remoteRules))
	}))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	loader, err := NewRemoteLoader(server.Client(), server.URL, NewRedactor(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = loader.LoadInitial(context.Background()); err == nil || otherCalled {
		t.Fatalf("followed redirect: %v, other=%v", err, otherCalled)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { loader.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("poller failed to stop")
	}
}

func TestRemoteRunAppliesRulesAfterExplicitEmptyStartup(t *testing.T) {
	var enabled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !enabled.Load() {
			_, _ = w.Write([]byte("schema_version=1\n[redaction]\nrules=[]"))
			return
		}
		_, _ = w.Write([]byte(remoteRules))
	}))
	defer server.Close()
	redactor := NewRedactor()
	loader, err := NewRemoteLoader(server.Client(), server.URL, redactor, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err = loader.LoadInitial(ctx); err != nil {
		t.Fatal(err)
	}
	if !loader.loaded || loader.status.Load().lastSuccess.IsZero() ||
		loader.status.Load().rules != 0 || redactor.HasRulesForHost("example.com") {
		t.Fatal("explicit empty config was not accepted as a successful no-redaction startup")
	}
	enabled.Store(true)
	done := make(chan struct{})
	go func() { loader.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("poller did not apply rules added after explicit empty startup")
		case <-tick.C:
			if string(applyBytes(redactor, "", []byte("secret"))) == "[hidden]" {
				return
			}
		}
	}
}

const self = "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d00"

// signer signs configs for tests, and serves the one stored last.
type signer struct {
	t    *testing.T
	key  *ecdsa.PrivateKey
	body atomic.Value
	url  string
}

func newSigner(t *testing.T) *signer {
	s := &signer{t: t, key: capabilitytest.Key("config")}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(s.body.Load().(string))) //nolint:forcetypeassert // test
	}))
	t.Cleanup(server.Close)
	s.url = server.URL
	return s
}

// sign is doc signed for connector at version, issued at issued and valid
// for a day.
func (s *signer) sign(connector string, version uint64, issued time.Time, doc string) string {
	b, err := signedconfig.Sign(s.key, "k", connector, version, issued,
		issued.Add(24*time.Hour), []byte(doc))
	if err != nil {
		s.t.Fatal(err)
	}
	return string(b)
}

// loader is a RemoteLoader for connector self, requiring s's signature,
// on redactor.
func (s *signer) loader(redactor *Redactor) *RemoteLoader {
	l, err := NewRemoteLoader(http.DefaultClient, s.url, redactor, time.Second)
	if err != nil {
		s.t.Fatal(err)
	}
	l.RequireSignature(self, map[string]*ecdsa.PublicKey{"k": &s.key.PublicKey})
	return l
}

// TestRemoteRequiresSignature: with config keys installed, only configs
// signed for this connector apply, each at a version above the one applied,
// and a refused one keeps the last-known-good rules. Another document at the
// applied version is refused; the same one re-signed (a retry) is a no-op.
func TestRemoteRequiresSignature(t *testing.T) {
	s := newSigner(t)
	// Every config here is issued at once, so the version decides.
	issued := time.Now()
	sign := func(connector string, version uint64, doc string) string {
		return s.sign(connector, version, issued, doc)
	}
	body := &s.body
	body.Store(sign(self, 5, remoteRules))
	redactor := NewRedactor()
	loader := s.loader(redactor)
	ctx := context.Background()
	if err := loader.LoadInitial(ctx); err != nil {
		t.Fatal(err)
	}
	accepted := redactor.rules.Load()
	updated := strings.Replace(remoteRules, "[hidden]", "[updated]", 1)
	for name, object := range map[string]string{
		"unsigned":               updated,
		"for a sibling":          sign("6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d01", 6, updated),
		"an older one":           sign(self, 4, updated),
		"another at its version": sign(self, 5, updated),
		"tampered after":         strings.Replace(sign(self, 6, updated), "[updated]", "[changed]", 1),
	} {
		body.Store(object)
		if err := loader.refresh(ctx); err == nil {
			t.Errorf("%s: applied", name)
		}
		if redactor.rules.Load() != accepted {
			t.Fatalf("%s: changed the rules", name)
		}
	}
	// The applied document re-signed at its version is a no-op.
	body.Store(sign(self, 5, remoteRules))
	if err := loader.refresh(ctx); err != nil {
		t.Fatalf("the applied config re-signed: %v", err)
	}
	if redactor.rules.Load() != accepted {
		t.Fatal("the applied config re-signed changed the rules")
	}
	// A newer one applies, and then its version is the floor.
	body.Store(sign(self, 6, strings.Replace(updated, "[updated]", "6", 1)))
	if err := loader.refresh(ctx); err != nil {
		t.Fatalf("version 6: %v", err)
	}
	if got := string(applyBytes(redactor, "", []byte("secret"))); got != "6" {
		t.Fatalf("newest config not applied: %q", got)
	}
	body.Store(sign(self, 6, updated))
	if err := loader.refresh(ctx); err == nil {
		t.Fatal("another document at version 6 applied")
	}
}

// TestRemoteSignedValidity: a signed config applies only within its validity
// window, and never if it was issued before the config applied, whatever its
// version. A restarted connector holds no applied config, so an expired one
// is what it refuses.
func TestRemoteSignedValidity(t *testing.T) {
	s := newSigner(t)
	ctx := context.Background()
	now := time.Now()
	for name, object := range map[string]string{
		"expired":                 s.sign(self, 5, now.Add(-25*time.Hour), remoteRules),
		"issued an hour from now": s.sign(self, 5, now.Add(time.Hour), remoteRules),
	} {
		s.body.Store(object)
		if err := s.loader(NewRedactor()).LoadInitial(ctx); err == nil {
			t.Errorf("%s: applied at startup", name)
		}
	}
	// Issued a minute ahead of this clock is within the skew allowed.
	s.body.Store(s.sign(self, 5, now.Add(time.Minute), remoteRules))
	redactor := NewRedactor()
	loader := s.loader(redactor)
	if err := loader.LoadInitial(ctx); err != nil {
		t.Fatalf("issued a minute ahead: %v", err)
	}
	accepted := redactor.rules.Load()
	updated := strings.Replace(remoteRules, "[hidden]", "[updated]", 1)
	// A higher version issued before the applied one is older: a signer
	// that reused versions cannot roll a connector back with it.
	s.body.Store(s.sign(self, 6, now.Add(-time.Hour), updated))
	if err := loader.refresh(ctx); err == nil || redactor.rules.Load() != accepted {
		t.Fatalf("a newer version issued earlier: %v", err)
	}
	// Issued at the same time, the version decides.
	s.body.Store(s.sign(self, 6, now.Add(time.Minute), updated))
	if err := loader.refresh(ctx); err != nil {
		t.Fatalf("version 6 issued with 5: %v", err)
	}
	if got := string(applyBytes(redactor, "", []byte("secret"))); got != "[updated]" {
		t.Fatalf("version 6 not applied: %q", got)
	}
}
