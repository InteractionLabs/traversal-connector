package redact

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// applyBytes drops Apply's "changed" flag for tests that assert only on the
// redacted output.
func applyBytes(r *Redactor, host string, src []byte) []byte {
	out, _ := r.Apply(context.Background(), host, src)
	return out
}

func TestRedactor_NoRules(t *testing.T) {
	r := NewRedactor()
	src := []byte("hello user@example.com world")
	got, _ := r.Apply(context.Background(), "", src)
	if &got[0] != &src[0] {
		t.Error("Apply with no rules should return the original slice unchanged")
	}
}

func TestRedactor_EmailRedaction(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Version: "v1",
		Rules: []Rule{
			{
				Name:        "email",
				Type:        ruleTypeRegex,
				Pattern:     `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
				Replacement: "[REDACTED_EMAIL]",
			},
		},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	got := string(applyBytes(r, "", []byte("contact user@example.com for help")))
	want := "contact [REDACTED_EMAIL] for help"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRedactor_SSNWithBackreference(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Version: "v1",
		Rules: []Rule{
			{
				Name:        "ssn",
				Type:        ruleTypeRegex,
				Pattern:     `\b\d{3}-\d{2}-(\d{4})\b`,
				Replacement: "***-**-$1",
			},
		},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	got := string(applyBytes(r, "", []byte("SSN: 123-45-6789")))
	want := "SSN: ***-**-6789"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRedactor_MultipleRules(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Version: "v1",
		Rules: []Rule{
			{
				Name:        "email",
				Type:        ruleTypeRegex,
				Pattern:     `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
				Replacement: "[REDACTED_EMAIL]",
			},
			{
				Name:        "ssn",
				Type:        ruleTypeRegex,
				Pattern:     `\b\d{3}-\d{2}-(\d{4})\b`,
				Replacement: "***-**-$1",
			},
		},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	got := string(applyBytes(r, "", []byte("user@example.com has SSN 123-45-6789")))
	want := "[REDACTED_EMAIL] has SSN ***-**-6789"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRedactor_InvalidPattern(t *testing.T) {
	r := NewRedactor()
	err := r.Update(&RulesFile{
		Rules: []Rule{{Name: "bad", Type: ruleTypeRegex, Pattern: `[invalid`}},
	})
	if err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
}

func TestRedactor_UnknownTypeSkipped(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{{Name: "x", Type: "glob", Pattern: "*.secret"}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}
	src := []byte("some.secret text")
	got, _ := r.Apply(context.Background(), "", src)
	if string(got) != string(src) {
		t.Errorf("unknown rule type should be skipped, got %q", got)
	}
}

func TestRedactor_AtomicUpdate(t *testing.T) {
	r := NewRedactor()

	// No rules yet — Apply is a no-op.
	original := []byte("user@example.com")
	if got := string(applyBytes(r, "", original)); got != "user@example.com" {
		t.Errorf("before update: got %q", got)
	}

	// Load rules.
	if err := r.Update(&RulesFile{
		Rules: []Rule{{
			Name:        "email",
			Type:        ruleTypeRegex,
			Pattern:     `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			Replacement: "[REDACTED_EMAIL]",
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}
	if got := string(applyBytes(r, "", []byte("user@example.com"))); got != "[REDACTED_EMAIL]" {
		t.Errorf("after update: got %q", got)
	}
}

func TestFileLoader_LoadInitial_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.toml")
	content := `version = "v1"
[[rules]]
name = "email"
type = "regex"
pattern = '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}'
replacement = "[REDACTED_EMAIL]"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewRedactor()
	l := NewFileLoader(path, r, 10*time.Second)
	if err := l.LoadInitial(); err != nil {
		t.Fatalf("LoadInitial() unexpected error: %v", err)
	}

	got := string(applyBytes(r, "", []byte("reach me at foo@bar.com")))
	want := "reach me at [REDACTED_EMAIL]"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFileLoader_LoadInitial_MissingFile(t *testing.T) {
	r := NewRedactor()
	l := NewFileLoader("/nonexistent/rules.toml", r, 10*time.Second)
	if err := l.LoadInitial(); err == nil {
		t.Fatal("LoadInitial() expected error for missing file, got nil")
	}
}

func TestFileLoader_LoadInitial_CorruptedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.toml")
	if err := os.WriteFile(path, []byte("not valid toml = [[[["), 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewRedactor()
	l := NewFileLoader(path, r, 10*time.Second)
	if err := l.LoadInitial(); err == nil {
		t.Fatal("LoadInitial() expected error for corrupted file, got nil")
	}
}

func TestFileLoader_LoadInitial_InvalidPattern(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.toml")
	content := `version = "v1"
[[rules]]
name = "bad"
type = "regex"
pattern = '[invalid'
replacement = "x"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewRedactor()
	l := NewFileLoader(path, r, 10*time.Second)
	if err := l.LoadInitial(); err == nil {
		t.Fatal("LoadInitial() expected error for invalid regex, got nil")
	}
}

func TestFileLoader_ReloadsOnChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.toml")

	// Start with no rules.
	if err := os.WriteFile(path, []byte(`version = "v1"`), 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewRedactor()
	l := NewFileLoader(path, r, 10*time.Second)
	if err := l.LoadInitial(); err != nil {
		t.Fatalf("LoadInitial() unexpected error: %v", err)
	}

	if got := string(applyBytes(r, "", []byte("foo@bar.com"))); got != "foo@bar.com" {
		t.Errorf("before update: expected unchanged, got %q", got)
	}

	// Write new rules and trigger a reload.
	newContent := `version = "v1"
[[rules]]
name = "email"
type = "regex"
pattern = '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}'
replacement = "[REDACTED_EMAIL]"
`
	if err := os.WriteFile(path, []byte(newContent), 0o600); err != nil {
		t.Fatal(err)
	}
	l.tryLoad()

	if got := string(applyBytes(r, "", []byte("foo@bar.com"))); got != "[REDACTED_EMAIL]" {
		t.Errorf("after reload: got %q", got)
	}
}

func TestFileLoader_DeletedAfterLoad_KeepsRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.toml")
	content := `version = "v1"
[[rules]]
name = "email"
type = "regex"
pattern = '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}'
replacement = "[REDACTED_EMAIL]"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewRedactor()
	l := NewFileLoader(path, r, 10*time.Second)
	if err := l.LoadInitial(); err != nil {
		t.Fatalf("LoadInitial() unexpected error: %v", err)
	}

	// Delete the file and trigger a periodic reload.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	l.tryLoad()

	// Rules should still be active.
	got := string(applyBytes(r, "", []byte("foo@bar.com")))
	want := "[REDACTED_EMAIL]"
	if got != want {
		t.Errorf("after delete: got %q, want %q (rules should be preserved)", got, want)
	}
}

func TestFileLoader_CorruptedAfterLoad_KeepsRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.toml")
	content := `version = "v1"
[[rules]]
name = "email"
type = "regex"
pattern = '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}'
replacement = "[REDACTED_EMAIL]"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewRedactor()
	l := NewFileLoader(path, r, 10*time.Second)
	if err := l.LoadInitial(); err != nil {
		t.Fatalf("LoadInitial() unexpected error: %v", err)
	}

	// Overwrite with corrupted content and trigger a periodic reload.
	if err := os.WriteFile(path, []byte("not valid toml = [[[["), 0o600); err != nil {
		t.Fatal(err)
	}
	l.tryLoad()

	// Rules should still be active.
	got := string(applyBytes(r, "", []byte("foo@bar.com")))
	want := "[REDACTED_EMAIL]"
	if got != want {
		t.Errorf("after corruption: got %q, want %q (rules should be preserved)", got, want)
	}
}

func TestHasRulesForHost(t *testing.T) {
	tests := []struct {
		name  string
		rules []Rule
		host  string
		want  bool
	}{
		{name: "no rules configured", host: "api.example.com"},
		{
			name:  "unscoped rule matches every host",
			rules: []Rule{{Name: "email", Type: "regex", Pattern: "a"}},
			host:  "api.example.com",
			want:  true,
		},
		{
			name: "host-scoped rule matches its host",
			rules: []Rule{
				{Name: "token", Type: "regex", Pattern: "a", Hosts: []string{`.*github\.com`}},
			},
			host: "api.github.com",
			want: true,
		},
		{
			name: "host-scoped rule ignores other hosts",
			rules: []Rule{
				{Name: "token", Type: "regex", Pattern: "a", Hosts: []string{`.*github\.com`}},
			},
			host: "api.example.com",
		},
		{
			name: "structured rules count too",
			rules: []Rule{
				{
					Name:    "email",
					Type:    "regex-structured-data",
					Pattern: "a",
					Hosts:   []string{`api\.example\.com`},
				},
			},
			host: "api.example.com",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRedactor()
			if err := r.Update(&RulesFile{Version: "v1", Rules: tt.rules}); err != nil {
				t.Fatalf("Update() error: %v", err)
			}
			if got := r.HasRulesForHost(tt.host); got != tt.want {
				t.Errorf("HasRulesForHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestApply_ReportsWhetherBodyChanged(t *testing.T) {
	tests := []struct {
		name        string
		rules       []Rule
		src         string
		wantChanged bool
	}{
		{name: "no rules configured", src: "user@example.com"},
		{
			name:        "a matching rule reports a change",
			rules:       []Rule{{Name: "email", Type: "regex", Pattern: `\S+@\S+`}},
			src:         "user@example.com",
			wantChanged: true,
		},
		{
			name:  "a rule that matches nothing reports no change",
			rules: []Rule{{Name: "email", Type: "regex", Pattern: `\S+@\S+`}},
			src:   "nothing sensitive",
		},
		{
			name: "a rule scoped to another host reports no change",
			rules: []Rule{
				{Name: "email", Type: "regex", Pattern: `\S+@\S+`, Hosts: []string{"other.test"}},
			},
			src: "user@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRedactor()
			if err := r.Update(&RulesFile{Version: "v1", Rules: tt.rules}); err != nil {
				t.Fatalf("Update() error: %v", err)
			}
			_, changed := r.Apply(context.Background(), "api.example.com", []byte(tt.src))
			if changed != tt.wantChanged {
				t.Errorf("changed = %v, want %v", changed, tt.wantChanged)
			}
		})
	}
}

func TestApplyJSON_ReportsWhetherBodyChanged(t *testing.T) {
	rules := []Rule{{
		Name:        "email",
		Type:        "regex-structured-data",
		Pattern:     `\S+@\S+`,
		Replacement: "[REDACTED]",
	}}

	tests := []struct {
		name        string
		src         string
		wantChanged bool
	}{
		{name: "a match reports a change", src: `{"msg":"user@example.com"}`, wantChanged: true},
		{name: "no match reports no change", src: `{"msg":"nothing sensitive"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRedactor()
			if err := r.Update(&RulesFile{Version: "v1", Rules: rules}); err != nil {
				t.Fatalf("Update() error: %v", err)
			}
			_, changed, err := r.ApplyJSON(context.Background(), "api.example.com", []byte(tt.src))
			if err != nil {
				t.Fatalf("ApplyJSON() error: %v", err)
			}
			if changed != tt.wantChanged {
				t.Errorf("changed = %v, want %v", changed, tt.wantChanged)
			}
		})
	}
}

func TestApplyJSON_ReSerializationIsNotAMatch(t *testing.T) {
	// ApplyJSON re-encodes the document, so a pretty-printed body comes back with
	// different bytes. That is not a redaction, and reporting it as one would
	// mark untouched responses as redacted.
	r := NewRedactor()
	if err := r.Update(&RulesFile{Version: "v1", Rules: []Rule{{
		Name:        "email",
		Type:        "regex-structured-data",
		Pattern:     `\S+@\S+`,
		Replacement: "[REDACTED]",
	}}}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	src := []byte("{\n  \"status\": \"ok\"\n}")
	got, changed, err := r.ApplyJSON(context.Background(), "api.example.com", src)
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}

	if changed {
		t.Error("re-serializing without a rule match must not report a change")
	}
	if want := `{"status":"ok"}`; string(got) != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}
