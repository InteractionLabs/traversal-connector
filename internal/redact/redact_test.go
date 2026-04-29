package redact

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)


func TestRedactor_NoRules(t *testing.T) {
	r := NewRedactor()
	src := []byte("hello user@example.com world")
	got := r.Apply(context.Background(), src)
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

	got := string(r.Apply(context.Background(), []byte("contact user@example.com for help")))
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

	got := string(r.Apply(context.Background(), []byte("SSN: 123-45-6789")))
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

	got := string(r.Apply(context.Background(), []byte("user@example.com has SSN 123-45-6789")))
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
	got := r.Apply(context.Background(), src)
	if string(got) != string(src) {
		t.Errorf("unknown rule type should be skipped, got %q", got)
	}
}

func TestRedactor_AtomicUpdate(t *testing.T) {
	r := NewRedactor()

	// No rules yet — Apply is a no-op.
	original := []byte("user@example.com")
	if got := string(r.Apply(context.Background(), original)); got != "user@example.com" {
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
	if got := string(r.Apply(context.Background(), []byte("user@example.com"))); got != "[REDACTED_EMAIL]" {
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

	got := string(r.Apply(context.Background(), []byte("reach me at foo@bar.com")))
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

	if got := string(r.Apply(context.Background(), []byte("foo@bar.com"))); got != "foo@bar.com" {
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

	if got := string(r.Apply(context.Background(), []byte("foo@bar.com"))); got != "[REDACTED_EMAIL]" {
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
	got := string(r.Apply(context.Background(), []byte("foo@bar.com")))
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
	got := string(r.Apply(context.Background(), []byte("foo@bar.com")))
	want := "[REDACTED_EMAIL]"
	if got != want {
		t.Errorf("after corruption: got %q, want %q (rules should be preserved)", got, want)
	}
}
