package redact

import (
	"fmt"
	"testing"
)

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
