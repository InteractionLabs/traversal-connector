package redact

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	tomlpkg "github.com/pelletier/go-toml/v2"
)

// --- default_replacement -----------------------------------------------------

func TestRedactor_DefaultReplacement_FallsBackToREDACTED(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{{
			Name:    "email",
			Type:    ruleTypeRegexStructured,
			Pattern: `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			// Replacement intentionally omitted.
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	got, err := r.ApplyJSON(context.Background(), "", []byte(`{"msg":"ping user@example.com"}`))
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}
	if !strings.Contains(string(got), `"msg":"ping [REDACTED]"`) {
		t.Errorf("got %q", got)
	}
}

func TestRedactor_DefaultReplacement_FileLevel(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		DefaultReplacement: "[HIDDEN]",
		Rules: []Rule{{
			Name:    "email",
			Type:    ruleTypeRegexStructured,
			Pattern: `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	got, err := r.ApplyJSON(context.Background(), "", []byte(`{"msg":"ping user@example.com"}`))
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}
	if !strings.Contains(string(got), `"msg":"ping [HIDDEN]"`) {
		t.Errorf("got %q", got)
	}
}

func TestRedactor_DefaultReplacement_RuleOverridesFile(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		DefaultReplacement: "[HIDDEN]",
		Rules: []Rule{{
			Name:        "email",
			Type:        ruleTypeRegexStructured,
			Pattern:     `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			Replacement: "[EMAIL]",
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	got, err := r.ApplyJSON(context.Background(), "", []byte(`{"msg":"ping user@example.com"}`))
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}
	if !strings.Contains(string(got), `"msg":"ping [EMAIL]"`) {
		t.Errorf("got %q", got)
	}
}

// --- ApplyJSON: no structured rules -> passthrough --------------------------

func TestRedactor_ApplyJSON_NoStructuredRules_ReturnsSrcUnchanged(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{{
			Name:        "legacy-email",
			Type:        ruleTypeRegex, // not structured
			Pattern:     `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			Replacement: "[EMAIL]",
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	src := []byte(`{"msg":"user@example.com"}`)
	got, err := r.ApplyJSON(context.Background(), "", src)
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}
	if string(got) != string(src) {
		t.Errorf("expected src unchanged, got %q", got)
	}
}

func TestRedactor_ApplyJSON_InvalidJSONReturnsError(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{{
			Name:    "email",
			Type:    ruleTypeRegexStructured,
			Pattern: `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	_, err := r.ApplyJSON(context.Background(), "", []byte("not json {{{"))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

// --- ApplyJSON: per-field redaction with no filters --------------------------

func TestRedactor_ApplyJSON_RedactsAllStringFields_NoFilters(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{{
			Name:        "email",
			Type:        ruleTypeRegexStructured,
			Pattern:     `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			Replacement: "[EMAIL]",
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	src := []byte(`{"message":"ping user@example.com","other":"meet bob@bar.io"}`)
	got, err := r.ApplyJSON(context.Background(), "", src)
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}

	// JSON ordering after Marshal is not guaranteed; assert on parsed shape.
	var parsed map[string]string
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, got)
	}
	if parsed["message"] != "ping [EMAIL]" {
		t.Errorf("message: got %q", parsed["message"])
	}
	if parsed["other"] != "meet [EMAIL]" {
		t.Errorf("other: got %q", parsed["other"])
	}
}

// --- ApplyJSON: redact_fields allowlist --------------------------------------

func TestRedactor_ApplyJSON_RedactFields_OnlyListedFieldsRedacted(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{{
			Name:         "email",
			Type:         ruleTypeRegexStructured,
			Pattern:      `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			Replacement:  "[EMAIL]",
			RedactFields: []string{"message"},
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	src := []byte(`{"message":"ping user@example.com","other":"meet bob@bar.io"}`)
	got, err := r.ApplyJSON(context.Background(), "", src)
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}

	var parsed map[string]string
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if parsed["message"] != "ping [EMAIL]" {
		t.Errorf("message should be redacted, got %q", parsed["message"])
	}
	if parsed["other"] != "meet bob@bar.io" {
		t.Errorf("other should NOT be redacted, got %q", parsed["other"])
	}
}

// --- ApplyJSON: skip_fields blocklist ----------------------------------------

func TestRedactor_ApplyJSON_SkipFields_ListedFieldsNotRedacted(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{{
			Name:        "email",
			Type:        ruleTypeRegexStructured,
			Pattern:     `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			Replacement: "[EMAIL]",
			SkipFields:  []string{"safe"},
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	src := []byte(`{"message":"ping user@example.com","safe":"meet bob@bar.io"}`)
	got, err := r.ApplyJSON(context.Background(), "", src)
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}

	var parsed map[string]string
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if parsed["message"] != "ping [EMAIL]" {
		t.Errorf("message should be redacted, got %q", parsed["message"])
	}
	if parsed["safe"] != "meet bob@bar.io" {
		t.Errorf("safe should NOT be redacted, got %q", parsed["safe"])
	}
}

// --- ApplyJSON: both filters set on same rule -- blocklist wins on overlap --

func TestRedactor_ApplyJSON_RedactAndSkip_BlocklistWinsOnOverlap(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{{
			Name:         "email",
			Type:         ruleTypeRegexStructured,
			Pattern:      `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			Replacement:  "[EMAIL]",
			RedactFields: []string{"a", "b"},
			SkipFields:   []string{"b"}, // overlap with allowlist
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	src := []byte(`{"a":"x@y.com","b":"x@y.com","c":"x@y.com"}`)
	got, err := r.ApplyJSON(context.Background(), "", src)
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}

	var parsed map[string]string
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if parsed["a"] != "[EMAIL]" {
		t.Errorf("a should be redacted (in allowlist, not in blocklist), got %q", parsed["a"])
	}
	if parsed["b"] != "x@y.com" {
		t.Errorf("b should NOT be redacted (in blocklist), got %q", parsed["b"])
	}
	if parsed["c"] != "x@y.com" {
		t.Errorf("c should NOT be redacted (not in allowlist), got %q", parsed["c"])
	}
}

// --- ApplyJSON: nested fields use pipe-delimited paths ----------------------

func TestRedactor_ApplyJSON_NestedFields_PipeDelimitedPath(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{{
			Name:         "email",
			Type:         ruleTypeRegexStructured,
			Pattern:      `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			Replacement:  "[EMAIL]",
			RedactFields: []string{"body|message"},
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	src := []byte(`{"body":{"message":"x@y.com","other":"a@b.com"},"top":"c@d.com"}`)
	got, err := r.ApplyJSON(context.Background(), "", src)
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	body := parsed["body"].(map[string]any)
	if body["message"] != "[EMAIL]" {
		t.Errorf("body|message should be redacted, got %q", body["message"])
	}
	if body["other"] != "a@b.com" {
		t.Errorf("body|other should NOT be redacted, got %q", body["other"])
	}
	if parsed["top"] != "c@d.com" {
		t.Errorf("top should NOT be redacted, got %q", parsed["top"])
	}
}

// --- ApplyJSON: arrays inherit parent field path ----------------------------

func TestRedactor_ApplyJSON_ArrayElementsInheritParentPath(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{{
			Name:         "email",
			Type:         ruleTypeRegexStructured,
			Pattern:      `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			Replacement:  "[EMAIL]",
			RedactFields: []string{"emails"},
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	src := []byte(`{"emails":["a@b.com","c@d.com"],"other":["e@f.com"]}`)
	got, err := r.ApplyJSON(context.Background(), "", src)
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}

	var parsed map[string][]string
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if parsed["emails"][0] != "[EMAIL]" || parsed["emails"][1] != "[EMAIL]" {
		t.Errorf("emails should both be redacted, got %v", parsed["emails"])
	}
	if parsed["other"][0] != "e@f.com" {
		t.Errorf("other should NOT be redacted, got %v", parsed["other"])
	}
}

// --- ApplyJSON: multiple rules with different filters ----------------------

func TestRedactor_ApplyJSON_MultipleRulesDifferentFields(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{
			{
				Name:         "email",
				Type:         ruleTypeRegexStructured,
				Pattern:      `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
				Replacement:  "[EMAIL]",
				RedactFields: []string{"message"},
			},
			{
				Name:         "ssn",
				Type:         ruleTypeRegexStructured,
				Pattern:      `\b\d{3}-\d{2}-\d{4}\b`,
				Replacement:  "[SSN]",
				RedactFields: []string{"notes"},
			},
		},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	src := []byte(`{"message":"a@b.com 123-45-6789","notes":"a@b.com 123-45-6789"}`)
	got, err := r.ApplyJSON(context.Background(), "", src)
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}

	var parsed map[string]string
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if parsed["message"] != "[EMAIL] 123-45-6789" {
		t.Errorf("message: got %q (only email rule should fire)", parsed["message"])
	}
	if parsed["notes"] != "a@b.com [SSN]" {
		t.Errorf("notes: got %q (only ssn rule should fire)", parsed["notes"])
	}
}

// --- Full-document Apply: structured rules are skipped entirely -------------

func TestRedactor_Apply_StructuredRule_DoesNotFireOnBytes(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{{
			Name:        "email",
			Type:        ruleTypeRegexStructured,
			Pattern:     `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			Replacement: "[EMAIL]",
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	// Structured rules only fire on the per-field ApplyJSON path. Apply leaves
	// the input untouched even when the pattern would match — without parsed
	// JSON there is no field to check redact_fields / skip_fields against.
	got := string(r.Apply(context.Background(), "", []byte("contact a@b.com")))
	want := "contact a@b.com"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// --- Mixed rule types: only legacy fires on Apply ---------------------------

func TestRedactor_Apply_MixedTypes_OnlyLegacyFires(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{
			{
				Name:        "legacy-email",
				Type:        ruleTypeRegex,
				Pattern:     `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
				Replacement: "[EMAIL]",
			},
			{
				Name:        "ssn",
				Type:        ruleTypeRegexStructured,
				Pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
				Replacement: "[SSN]",
			},
		},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	// Only the legacy regex rule fires byte-level; the structured rule is skipped.
	got := string(r.Apply(context.Background(), "", []byte("a@b.com / 123-45-6789")))
	want := "[EMAIL] / 123-45-6789"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRedactor_ApplyJSON_LegacyRegexRulesAreIgnored(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{
			{
				Name:        "legacy-email",
				Type:        ruleTypeRegex, // not structured -> won't fire per-field
				Pattern:     `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
				Replacement: "[EMAIL]",
			},
			{
				Name:        "ssn",
				Type:        ruleTypeRegexStructured,
				Pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
				Replacement: "[SSN]",
			},
		},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	src := []byte(`{"msg":"a@b.com / 123-45-6789"}`)
	got, err := r.ApplyJSON(context.Background(), "", src)
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}

	var parsed map[string]string
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	// Email NOT redacted (legacy regex rule doesn't apply on per-field path);
	// SSN IS redacted.
	if parsed["msg"] != "a@b.com / [SSN]" {
		t.Errorf("got %q (legacy regex should not fire on JSON)", parsed["msg"])
	}
}

// --- Loaded via TOML: end-to-end exercising the new schema ------------------

func TestRedactor_TOML_StructuredRuleWithFilters(t *testing.T) {
	const tomlSrc = `
default_replacement = "[X]"

# Email rule has no field filter: applies to every field.
[[rules]]
name = "email"
type = "regex-structured-data"
pattern = '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}'

# SSN rule skips meta|hostname only.
[[rules]]
name = "ssn"
type = "regex-structured-data"
pattern = '\d{3}-\d{2}-\d{4}'
replacement = "[SSN]"
skip_fields = ["meta|hostname"]
`
	var f RulesFile
	if err := tomlpkg.Unmarshal([]byte(tomlSrc), &f); err != nil {
		t.Fatalf("toml unmarshal: %v", err)
	}

	r := NewRedactor()
	if err := r.Update(&f); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	src := []byte(
		`{"body":{"message":"a@b.com 123-45-6789"},"meta":{"hostname":"a@b.com 123-45-6789"}}`,
	)
	got, err := r.ApplyJSON(context.Background(), "", src)
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}

	out := string(got)
	// body|message: both rules fire — email uses default_replacement "[X]", ssn uses its own "[SSN]".
	if !strings.Contains(out, `"message":"[X] [SSN]"`) {
		t.Errorf("expected body|message to be fully redacted; got %s", out)
	}
	// meta|hostname: email rule fires (no filter), ssn rule is skipped via skip_fields.
	if !strings.Contains(out, `"hostname":"[X] 123-45-6789"`) {
		t.Errorf("expected meta|hostname to have email redacted but ssn skipped; got %s", out)
	}
}

// --- New scope semantics: keys redacted, subtree match, top-level array -----

func TestRedactor_ApplyJSON_NoFilter_RedactsKeysAndValues(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{{
			Name:        "email",
			Type:        ruleTypeRegexStructured,
			Pattern:     `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			Replacement: "[EMAIL]",
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	src := []byte(`{"user@example.com":"bob@bar.io","plain":"no email here"}`)
	got, err := r.ApplyJSON(context.Background(), "", src)
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}

	var parsed map[string]string
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if _, ok := parsed["[EMAIL]"]; !ok {
		t.Errorf("expected email-shaped key to be redacted; got %s", got)
	}
	if parsed["[EMAIL]"] != "[EMAIL]" {
		t.Errorf("expected value redacted alongside key; got %q", parsed["[EMAIL]"])
	}
	if parsed["plain"] != "no email here" {
		t.Errorf("non-matching key/value should pass through; got %q", parsed["plain"])
	}
}

func TestRedactor_ApplyJSON_RedactFields_AppliesToEntireSubtree(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{{
			Name:         "email",
			Type:         ruleTypeRegexStructured,
			Pattern:      `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			Replacement:  "[EMAIL]",
			RedactFields: []string{"data"},
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	// Filter is "data" — every primary leaf reachable from "data" gets redacted,
	// regardless of nesting depth. "other" is outside the subtree and is left alone.
	src := []byte(
		`{"data":{"nested":{"deep":"a@b.com"},"arr":["c@d.com","plain"]},"other":"e@f.com"}`,
	)
	got, err := r.ApplyJSON(context.Background(), "", src)
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}

	out := string(got)
	if !strings.Contains(out, `"deep":"[EMAIL]"`) {
		t.Errorf("data|nested|deep should be redacted; got %s", out)
	}
	if !strings.Contains(out, `["[EMAIL]","plain"]`) {
		t.Errorf(
			"array elements under data should be redacted, non-matching item left alone; got %s",
			out,
		)
	}
	if !strings.Contains(out, `"other":"e@f.com"`) {
		t.Errorf("top-level field outside the subtree should not be redacted; got %s", out)
	}
}

func TestRedactor_ApplyJSON_RedactFields_RedactsNestedKeysInsideSubtree(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{{
			Name:         "email",
			Type:         ruleTypeRegexStructured,
			Pattern:      `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			Replacement:  "[EMAIL]",
			RedactFields: []string{"data"},
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	// Inside the "data" subtree, keys are redacted too. The addressing key
	// "data" itself is at the parent scope (root), which is NOT in scope, so
	// it stays intact.
	src := []byte(`{"data":{"a@b.com":"value"}}`)
	got, err := r.ApplyJSON(context.Background(), "", src)
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}

	out := string(got)
	if !strings.Contains(out, `"data":`) {
		t.Errorf("the addressing key 'data' should not be redacted; got %s", out)
	}
	if !strings.Contains(out, `"[EMAIL]":"value"`) {
		t.Errorf("nested key inside data should be redacted; got %s", out)
	}
}

func TestRedactor_ApplyJSON_TopLevelArray_NoFilter(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{{
			Name:        "email",
			Type:        ruleTypeRegexStructured,
			Pattern:     `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			Replacement: "[EMAIL]",
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	got, err := r.ApplyJSON(context.Background(), "", []byte(`["a@b.com","c@d.com","plain"]`))
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}

	var parsed []string
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	want := []string{"[EMAIL]", "[EMAIL]", "plain"}
	for i, w := range want {
		if parsed[i] != w {
			t.Errorf("element %d: got %q, want %q", i, parsed[i], w)
		}
	}
}

func TestRedactor_ApplyJSON_NumberMatching_RewrittenAsString(t *testing.T) {
	r := NewRedactor()
	// A credit-card-shaped pattern — matches a 16-digit run whether it's
	// stored as a JSON string or a JSON number.
	if err := r.Update(&RulesFile{
		Rules: []Rule{{
			Name:        "cc",
			Type:        ruleTypeRegexStructured,
			Pattern:     `\b\d{16}\b`,
			Replacement: "[CC]",
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	src := []byte(`{"as_string":"4111111111111111","as_number":4111111111111111,"untouched":42}`)
	got, err := r.ApplyJSON(context.Background(), "", src)
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}

	out := string(got)
	if !strings.Contains(out, `"as_string":"[CC]"`) {
		t.Errorf("string-encoded number should be redacted; got %s", out)
	}
	// A matched number is rewritten as a JSON string (with quotes), since the
	// redacted text is no longer a valid number.
	if !strings.Contains(out, `"as_number":"[CC]"`) {
		t.Errorf("number-encoded credit card should be redacted as a string; got %s", out)
	}
	// A number that doesn't match the pattern stays a number (no quotes).
	if !strings.Contains(out, `"untouched":42`) || strings.Contains(out, `"untouched":"42"`) {
		t.Errorf("non-matching number should remain a number; got %s", out)
	}
}

func TestRedactor_ApplyJSON_SkipFields_ExcludesSubtreeIncludingKey(t *testing.T) {
	r := NewRedactor()
	if err := r.Update(&RulesFile{
		Rules: []Rule{{
			Name:        "email",
			Type:        ruleTypeRegexStructured,
			Pattern:     `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			Replacement: "[EMAIL]",
			SkipFields:  []string{"safe"},
		}},
	}); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	// "safe" is skipped: neither the key nor anything inside it is touched,
	// even though there's no whitelist and the rule otherwise applies everywhere.
	src := []byte(`{"data":"a@b.com","safe":{"inner":"c@d.com","other":"plain"}}`)
	got, err := r.ApplyJSON(context.Background(), "", src)
	if err != nil {
		t.Fatalf("ApplyJSON() error: %v", err)
	}

	out := string(got)
	if !strings.Contains(out, `"data":"[EMAIL]"`) {
		t.Errorf("data should be redacted; got %s", out)
	}
	if !strings.Contains(out, `"safe":{`) {
		t.Errorf("safe key should not be redacted; got %s", out)
	}
	if !strings.Contains(out, `"inner":"c@d.com"`) {
		t.Errorf("contents under safe should not be redacted; got %s", out)
	}
}
