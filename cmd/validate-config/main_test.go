package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestValidateConfigCommand(t *testing.T) {
	const rule = "schema_version=1\n[redaction]\n[[redaction.rules]]\nname='test'\ntype='regex'\npattern="
	for _, tc := range []struct {
		name, config string
		want         int
	}{
		{"empty_rules", "schema_version=1\n[redaction]\nrules=[]", 0},
		{"go_re2", rule + `'\p{Greek}+'` + "\nhosts=['.*']", 0},
		{"malformed", rule + "'['\nhosts=['.*']", 1},
		{"lookbehind", rule + "'(?<=secret)value'\nhosts=['.*']", 1},
		// v0.9 configs: a rule without hosts covers every host.
		{"no_hosts", rule + "'x'", 0},
		{"empty_hosts", rule + "'x'\nhosts=[]", 0},
		{"host_malformed", rule + "'x'\nhosts=['[']", 1},
		{"host_lookbehind", rule + "'x'\nhosts=['(?<=a)b']", 1},
		{"wildcard_first", rule + "'x'\nhosts=['.*','[']", 1},
		{"wildcard_last", rule + "'x'\nhosts=['[','.*']", 1},
		{"valid_hosts", rule + "'x'\nhosts=['api\\.example\\.com','.*']", 0},
		{"invalid_toml", "not a config", 1},
		{"oversized", strings.Repeat(" ", 1024*1024+1), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var diagnostics bytes.Buffer
			if got := run(nil, strings.NewReader(tc.config), &diagnostics); got != tc.want {
				t.Fatalf("exit=%d want=%d: %s", got, tc.want, diagnostics.String())
			}
			if strings.Contains(diagnostics.String(), "secret") {
				t.Fatal("diagnostics leaked regex contents")
			}
		})
	}
	var diagnostics bytes.Buffer
	if code := run([]string{"unexpected"}, strings.NewReader(""), &diagnostics); code != 2 {
		t.Fatal("unexpected arguments accepted")
	}
}
