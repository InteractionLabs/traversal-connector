package redact

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
