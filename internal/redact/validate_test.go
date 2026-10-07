package redact

import (
	"fmt"
	"strings"
	"testing"
)

func TestParserAndOfflineValidatorAgreeOnRuleTypes(t *testing.T) {
	for _, tc := range []struct {
		name, typeField string
		valid           bool
	}{
		{name: "regex", typeField: `type = "regex"`, valid: true},
		{name: "structured", typeField: `type = "regex-structured-data"`, valid: true},
		{name: "unsupported", typeField: `type = "glob"`},
		{name: "empty", typeField: `type = ""`},
		{name: "omitted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(strings.Replace(remoteRules, `type = "regex"`, tc.typeField, 1))
			if _, err := ParseConfig(data); (err == nil) != tc.valid {
				t.Fatalf("unexpected parser result: %v", err)
			}
			if err := ValidateConfig(data); (err == nil) != tc.valid {
				t.Fatalf("unexpected offline validation result: %v", err)
			}
		})
	}
}

func TestOfflineValidatorAgreesWithRuntime(t *testing.T) {
	for _, tc := range []struct {
		pattern, hosts string
		valid          bool
	}{
		{"x", "[]", true},
		{"[", "[]", false},
		{"(?<=a)b", "[]", false},
		{`\p{Greek}+`, `['api\.example\.com']`, true},
		{"x", "['[']", false},
		{"x", "['(?<=a)b']", false},
		{"x", "['.*','[']", false},
		{"x", "['[','.*']", false},
		{"x", "['.*','api']", true},
	} {
		t.Run(tc.pattern+tc.hosts, func(t *testing.T) {
			data := []byte(fmt.Sprintf(
				"schema_version=1\n[redaction]\n[[redaction.rules]]\nname='rule'\ntype='regex'\npattern='%s'\nhosts=%s",
				tc.pattern,
				tc.hosts,
			))
			rules, err := ParseConfig(data)
			if err != nil {
				t.Fatal(err)
			}
			if (NewRedactor().Update(rules) == nil) != tc.valid {
				t.Fatal("unexpected runtime compilation result")
			}
			if (ValidateConfig(data) == nil) != tc.valid {
				t.Fatal("validator disagrees with runtime")
			}
		})
	}
}
