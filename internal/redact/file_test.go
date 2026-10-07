package redact

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const localRules = `version = "v1"
default_replacement = "[LOCAL]"
[[rules]]
name = "token"
type = "regex"
pattern = 'secret'
`

func writeLocalRules(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFileLoaderInitial(t *testing.T) {
	for _, tc := range []struct {
		name, content, want string
		wantErr             bool
	}{
		{name: "legacy rules", content: localRules, want: "[LOCAL]"},
		{name: "explicit empty", content: "rules=[]", want: "secret"},
		{name: "legacy version only", content: `version="v1"`, want: "secret"},
		{name: "invalid TOML", content: "CUSTOMER_CANARY = [", wantErr: true},
		{name: "invalid pattern", content: strings.ReplaceAll(localRules, "'secret'", "'[CUSTOMER_CANARY'"), wantErr: true},
		{name: "invalid host", content: localRules + "\nhosts=['.*', '[CUSTOMER_CANARY']", wantErr: true},
		{name: "unsupported type", content: strings.ReplaceAll(localRules, `"regex"`, `"CUSTOMER_CANARY"`), wantErr: true},
		{name: "omitted type", content: strings.ReplaceAll(localRules, "type = \"regex\"\n", ""), wantErr: true},
		{name: "mixed valid and invalid types", content: localRules + "\n[[rules]]\nname='bad'\ntype='CUSTOMER_CANARY'\npattern='secret'", wantErr: true},
		{name: "unknown top-level field", content: "owner='security'\n" + localRules, want: "[LOCAL]"},
		{name: "unknown rule field", content: localRules + "\nCUSTOMER_CANARY=true", want: "[LOCAL]"},
		{name: "unknown rule table", content: localRules + "\n[rules.metadata]\nowner='security'", want: "[LOCAL]"},
		{name: "unknown top-level table", content: localRules + "\n[metadata]\nowner='security'", want: "[LOCAL]"},
		{name: "unknown fields without rules", content: "owner='security'\n[metadata]\nnote='empty'", want: "secret"},
		{name: "schema version metadata without rules", content: "schema_version='custom'", want: "secret"},
		{name: "redaction metadata without rules", content: "[redaction]\nowner='security'", want: "secret"},
		{name: "OTA fields alongside local rules", content: "schema_version=1\n" + localRules + "\n[redaction]\nrules=[]", want: "[LOCAL]"},
		{name: "remote format is not a local rules file", content: remoteRules, wantErr: true},
		{name: "empty remote config is not a local rules file", content: "schema_version=1\n[redaction]\nrules=[]", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rules.toml")
			writeLocalRules(t, path, tc.content)
			r := NewRedactor()
			l := NewFileLoader(path, r, time.Second)
			err := l.LoadInitial()
			if tc.wantErr {
				if err == nil {
					t.Fatal("invalid config accepted")
				}
				if strings.Contains(err.Error(), "CUSTOMER_CANARY") {
					t.Fatalf("rule contents leaked: %v", err)
				}
				if l.loaded {
					t.Fatal("invalid config marked loaded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := string(applyBytes(r, "", []byte("secret"))); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFileLoaderInvalidSettings(t *testing.T) {
	r := NewRedactor()
	path := filepath.Join(t.TempDir(), "missing.toml")
	for _, l := range []*FileLoader{
		NewFileLoader(path, r, time.Second),
		NewFileLoader("", r, time.Second),
		NewFileLoader(path, nil, time.Second),
		NewFileLoader(path, r, 0),
		NewFileLoader(path, r, -time.Second),
	} {
		if err := l.LoadInitial(); err == nil {
			t.Fatal("invalid loader or missing file accepted")
		}
		if err := l.Run(context.Background()); err == nil {
			t.Fatal("polling allowed before initial load")
		}
	}
}

func TestFileLoaderReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.toml")
	writeLocalRules(t, path, localRules)
	r := NewRedactor()
	l := NewFileLoader(path, r, time.Second)
	if err := l.LoadInitial(); err != nil {
		t.Fatal(err)
	}
	original := r.rules.Load()
	if err := l.refresh(); err != nil || r.rules.Load() != original {
		t.Fatalf("unchanged rules recompiled: %v", err)
	}
	acceptedHash := l.lastHash
	for _, bad := range []string{
		"invalid = [",
		strings.ReplaceAll(localRules, "'secret'", "'['"),
		remoteRules,
		strings.ReplaceAll(localRules, `"regex"`, `"glob"`),
		strings.ReplaceAll(localRules, "type = \"regex\"\n", ""),
		localRules + "\n[[rules]]\nname='bad'\ntype='glob'\npattern='secret'",
		localRules + "\n[[rules]]\nname='bad'\npattern='secret'",
	} {
		writeLocalRules(t, path, bad)
		if err := l.refresh(); err == nil {
			t.Fatal("invalid update accepted")
		}
		if r.rules.Load() != original || l.lastHash != acceptedHash {
			t.Fatal("invalid update changed rules or accepted hash")
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := l.refresh(); err == nil || r.rules.Load() != original {
		t.Fatalf("deleted file must retain rules: %v", err)
	}
	writeLocalRules(t, path, "owner='security'\n"+
		strings.ReplaceAll(localRules, "[LOCAL]", "[UPDATED]")+
		"\nreason='extra rule metadata'\n[rules.metadata]\nowner='security'")
	if err := l.refresh(); err != nil {
		t.Fatal(err)
	}
	if got := string(applyBytes(r, "", []byte("secret"))); got != "[UPDATED]" {
		t.Fatalf("updated rules not applied: %s", got)
	}
	writeLocalRules(t, path, "rules=[]")
	if err := l.refresh(); err != nil || r.HasRulesForHost("example.com") {
		t.Fatalf("explicit empty rules not applied: %v", err)
	}
}

func TestFileLoaderFailureLimitAndRecovery(t *testing.T) {
	for _, recovery := range []string{
		localRules,
		strings.ReplaceAll(localRules, "[LOCAL]", "[NEW]"),
		"owner='security'\n" + localRules + "\nnote='extra rule metadata'",
	} {
		t.Run(recovery, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rules.toml")
			writeLocalRules(t, path, localRules)
			r := NewRedactor()
			l := NewFileLoader(path, r, time.Second)
			if err := l.LoadInitial(); err != nil {
				t.Fatal(err)
			}
			writeLocalRules(t, path, "bad=[")
			for range 2 {
				if err := l.poll(context.Background()); err != nil {
					t.Fatal("stopped before three failures")
				}
			}
			writeLocalRules(t, path, recovery)
			if err := l.poll(context.Background()); err != nil || l.consecutiveFailures != 0 {
				t.Fatalf("successful read did not reset failures: %v", err)
			}
			writeLocalRules(t, path, "bad=[")
			for range 2 {
				if err := l.poll(context.Background()); err != nil {
					t.Fatal("old failures counted after recovery")
				}
			}
			if err := l.poll(context.Background()); err == nil {
				t.Fatal("third consecutive failure did not stop polling")
			}
			if !r.HasRulesForHost("example.com") {
				t.Fatal("reload failures disabled redaction")
			}
		})
	}
}

func TestFileLoaderRunHotReloadAndCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.toml")
	first, second := filepath.Join(dir, "first.toml"), filepath.Join(dir, "second.toml")
	writeLocalRules(t, first, "rules=[]")
	writeLocalRules(t, second, localRules)
	if err := os.Symlink(first, path); err != nil {
		t.Fatal(err)
	}
	r := NewRedactor()
	l := NewFileLoader(path, r, time.Millisecond)
	if err := l.LoadInitial(); err != nil {
		t.Fatal(err)
	}
	// Directory-mounted ConfigMaps and Secrets replace symlinks on update.
	next := filepath.Join(dir, "next")
	if err := os.Symlink(second, next); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	for !r.HasRulesForHost("example.com") && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := string(applyBytes(r, "", []byte("secret"))); got != "[LOCAL]" {
		t.Fatalf("symlink replacement not reloaded: %s", got)
	}
}

func TestFileLoaderRunStopsOnRepeatedFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.toml")
	writeLocalRules(t, path, localRules)
	l := NewFileLoader(path, NewRedactor(), time.Millisecond)
	if err := l.LoadInitial(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := l.Run(ctx); err == nil || !strings.Contains(err.Error(), "3 consecutive") {
		t.Fatalf("expected failure after three attempts, got %v", err)
	}
}
