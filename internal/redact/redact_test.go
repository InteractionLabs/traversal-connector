package redact

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

// TestHostMatchingFollowsDNSSpelling checks every entry point that takes a host
// against the same cases. The gate and per-rule matching have to reach the same
// verdict for a given spelling: if the gate said no while a rule said yes, the
// response would skip decoding and rule evaluation altogether.
func TestHostMatchingFollowsDNSSpelling(t *testing.T) {
	tests := []struct {
		name        string
		hostPattern string
		host        string
		want        bool
	}{
		{name: "exact match", hostPattern: `example\.com`, host: "example.com", want: true},
		{
			name:        "requested host in upper case",
			hostPattern: `example\.com`,
			host:        "EXAMPLE.COM",
			want:        true,
		},
		{
			name:        "requested host in mixed case",
			hostPattern: `example\.com`,
			host:        "Example.Com",
			want:        true,
		},
		{
			name:        "requested host with a trailing dot",
			hostPattern: `example\.com`,
			host:        "example.com.",
			want:        true,
		},
		{
			name:        "requested host in upper case with a trailing dot",
			hostPattern: `example\.com`,
			host:        "EXAMPLE.COM.",
			want:        true,
		},
		{
			// Rule files predate case folding, so any pattern already written
			// with capitals has to keep working.
			name:        "pattern written in upper case",
			hostPattern: `EXAMPLE\.COM`,
			host:        "example.com",
			want:        true,
		},
		{
			name:        "pattern and host both in upper case",
			hostPattern: `EXAMPLE\.COM`,
			host:        "EXAMPLE.COM",
			want:        true,
		},
		{
			name:        "lower-case character class matches an upper-case host",
			hostPattern: `[a-z]+\.example\.com`,
			host:        "API.EXAMPLE.COM",
			want:        true,
		},
		{
			name:        "a different host does not match",
			hostPattern: `example\.com`,
			host:        "notexample.com",
		},
		{
			name:        "a longer host does not match through the anchors",
			hostPattern: `example\.com`,
			host:        "example.com.other.com",
		},
		{
			// Only one trailing dot marks an absolute name; a second leaves an
			// empty label, which is not a name this rule was scoped to.
			name:        "a doubled trailing dot does not match",
			hostPattern: `example\.com`,
			host:        "example.com..",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRedactor()
			if err := r.Update(&RulesFile{Version: "v1", Rules: []Rule{
				{
					Name:        "byte-level",
					Type:        "regex",
					Pattern:     "secret",
					Replacement: "[REDACTED]",
					Hosts:       []string{tt.hostPattern},
				},
				{
					Name:        "per-field",
					Type:        "regex-structured-data",
					Pattern:     "secret",
					Replacement: "[REDACTED]",
					Hosts:       []string{tt.hostPattern},
				},
			}}); err != nil {
				t.Fatalf("Update() error: %v", err)
			}

			if got := r.HasRulesForHost(tt.host); got != tt.want {
				t.Errorf("HasRulesForHost(%q) = %v, want %v", tt.host, got, tt.want)
			}

			_, byteChanged := r.Apply(context.Background(), tt.host, []byte("secret"))
			if byteChanged != tt.want {
				t.Errorf("Apply(%q) changed = %v, want %v", tt.host, byteChanged, tt.want)
			}

			_, fieldChanged, err := r.ApplyJSON(
				context.Background(), tt.host, []byte(`{"k":"secret"}`),
			)
			if err != nil {
				t.Fatalf("ApplyJSON() error: %v", err)
			}
			if fieldChanged != tt.want {
				t.Errorf("ApplyJSON(%q) changed = %v, want %v", tt.host, fieldChanged, tt.want)
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

func TestApplyJSON_RequiresExactlyOneDocument(t *testing.T) {
	rules := []Rule{{
		Name:        "email",
		Type:        "regex-structured-data",
		Pattern:     `\S+@\S+`,
		Replacement: "[REDACTED]",
	}}

	tests := []struct {
		name    string
		src     string
		wantErr bool
	}{
		{name: "one object", src: `{"msg":"user@example.com"}`},
		{name: "one array", src: `[{"msg":"user@example.com"}]`},
		{name: "one bare string", src: `"user@example.com"`},
		{name: "trailing whitespace is still one document", src: "{\"msg\":\"a@b.com\"}\n\t "},
		{name: "truncated object", src: `{"msg":`, wantErr: true},
		{name: "not json at all", src: `nope`, wantErr: true},
		{name: "empty body", src: ``, wantErr: true},
		{name: "two concatenated documents", src: `{"a":1}{"b":2}`, wantErr: true},
		{name: "two documents separated by space", src: `{"a":1} {"b":2}`, wantErr: true},
		{name: "junk after a complete value", src: `{"a":1}garbage`, wantErr: true},
		{
			// A closing bracket reads as the end of an enclosing array rather
			// than as a further value, so it is the shape most likely to slip
			// past a looser check for whether more input follows.
			name:    "stray closing bracket after a complete value",
			src:     `{"a":1}]`,
			wantErr: true,
		},
		{name: "stray comma after a complete value", src: `{"a":1},`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRedactor()
			if err := r.Update(&RulesFile{Version: "v1", Rules: rules}); err != nil {
				t.Fatalf("Update() error: %v", err)
			}

			_, _, err := r.ApplyJSON(context.Background(), "api.example.com", []byte(tt.src))
			if tt.wantErr && err == nil {
				t.Errorf("ApplyJSON(%q) returned no error, want one", tt.src)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ApplyJSON(%q) error = %v, want none", tt.src, err)
			}
		})
	}
}

func TestApplyJSON_FaultDescribesWhatWentWrong(t *testing.T) {
	rules := []Rule{{Name: "email", Type: "regex-structured-data", Pattern: `\S+@\S+`}}

	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a genuine second document says so",
			src:  `{"a":1} {"b":2}`,
			want: "more than one document, the first ends at byte 7",
		},
		{
			// Reporting these as a second document would send an operator looking
			// for one that is not there.
			name: "unparseable trailing bytes are not called a document",
			src:  `{"a":1}XY`,
			want: "trailing bytes that do not parse at byte 8",
		},
		{
			name: "a stray bracket is also trailing bytes",
			src:  `{"a":1}]`,
			want: "trailing bytes that do not parse at byte 7",
		},
		{
			name: "a body that is not json at all",
			src:  `XYnope`,
			want: "json body does not parse at byte 1",
		},
		{
			name: "a truncated document is reported as truncated",
			src:  `{"a":`,
			want: "ends mid-document",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRedactor()
			if err := r.Update(&RulesFile{Version: "v1", Rules: rules}); err != nil {
				t.Fatalf("Update() error: %v", err)
			}

			_, _, err := r.ApplyJSON(context.Background(), "api.example.com", []byte(tt.src))
			if err == nil {
				t.Fatalf("ApplyJSON(%q) returned no error, want one", tt.src)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

// TestApplyJSON_FaultCarriesNoBodyContent guards the boundary the drop exists to
// hold. A refused body is not forwarded, so no part of it may ride out on the
// error describing the refusal either, however far that error is later carried.
// The decoder's own messages quote the byte they stopped on, so the marker below
// is upper case where every word the redactor emits is lower case.
func TestApplyJSON_FaultCarriesNoBodyContent(t *testing.T) {
	const marker = "ZZQQ"

	tests := []struct {
		name string
		src  string
	}{
		{name: "junk after a complete document", src: `{"a":1}` + marker},
		{name: "a body that is not json at all", src: marker + `nope`},
		{name: "junk inside a document", src: `{"a":` + marker + `}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRedactor()
			if err := r.Update(&RulesFile{Version: "v1", Rules: []Rule{
				{Name: "email", Type: "regex-structured-data", Pattern: `\S+@\S+`},
			}}); err != nil {
				t.Fatalf("Update() error: %v", err)
			}

			_, _, err := r.ApplyJSON(context.Background(), "api.example.com", []byte(tt.src))
			if err == nil {
				t.Fatalf("ApplyJSON(%q) returned no error, want one", tt.src)
			}
			for _, char := range []string{"Z", "Q"} {
				if strings.Contains(err.Error(), char) {
					t.Errorf("error %q carries %q from the body", err, char)
				}
			}
		})
	}
}

// TestApplyJSON_UnparseableBodyIsNotAnErrorWithoutStructuredRules pins the
// narrowness of the parse requirement: it exists to serve per-field rules, so a
// host none of them cover must not start failing on bodies nothing would have
// inspected.
func TestApplyJSON_UnparseableBodyIsNotAnErrorWithoutStructuredRules(t *testing.T) {
	tests := []struct {
		name  string
		rules []Rule
	}{
		{name: "no rules configured"},
		{
			name:  "only a byte-level rule",
			rules: []Rule{{Name: "email", Type: "regex", Pattern: `\S+@\S+`}},
		},
		{
			name: "structured rule scoped to another host",
			rules: []Rule{{
				Name:    "email",
				Type:    "regex-structured-data",
				Pattern: `\S+@\S+`,
				Hosts:   []string{"other.test"},
			}},
		},
	}

	src := []byte(`{"msg":"user@example.com" trailing junk`)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRedactor()
			if err := r.Update(&RulesFile{Version: "v1", Rules: tt.rules}); err != nil {
				t.Fatalf("Update() error: %v", err)
			}

			got, changed, err := r.ApplyJSON(context.Background(), "api.example.com", src)
			if err != nil {
				t.Fatalf("ApplyJSON() error = %v, want none", err)
			}
			if changed {
				t.Error("no structured rule was in scope, so nothing can have matched")
			}
			if string(got) != string(src) {
				t.Errorf("body = %q, want it returned unchanged", got)
			}
		})
	}
}
