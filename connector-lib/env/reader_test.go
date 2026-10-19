package env_test

import (
	"strings"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/env"
)

// TestReader: unset settings take their defaults; invalid ones are each an
// error, never their default.
func TestReader(t *testing.T) {
	t.Setenv("R_INT", "")
	t.Setenv("R_DUR", "")
	t.Setenv("R_BOOL", "")
	var r env.Reader
	if r.Int("R_INT", 3, 8) != 3 || r.Duration("R_DUR", time.Minute) != time.Minute ||
		r.Bool("R_BOOL", false) || !r.Bool("R_BOOL", true) || r.Err() != nil {
		t.Fatalf("unset: %v", r.Err())
	}
	t.Setenv("R_INT", "8")
	t.Setenv("R_DUR", "15m")
	t.Setenv("R_BOOL", "true")
	if r.Int("R_INT", 3, 8) != 8 || r.Duration("R_DUR", 0) != 15*time.Minute ||
		!r.Bool("R_BOOL", false) || r.Err() != nil {
		t.Fatalf("valid: %v", r.Err())
	}

	for key, bad := range map[string][]string{
		"R_INT":  {"0", "9", "x", "1.5"},
		"R_DUR":  {"15", "-1s", "soon"},
		"R_BOOL": {"1", "T", "yes", "TRUE"},
	} {
		for _, v := range bad {
			t.Setenv(key, v)
			var r env.Reader
			switch key {
			case "R_INT":
				r.Int(key, 3, 8)
			case "R_DUR":
				r.Duration(key, time.Minute)
			case "R_BOOL":
				r.Bool(key, false)
			}
			if err := r.Err(); err == nil || !strings.Contains(err.Error(), key) {
				t.Errorf("%s=%q: %v, want an error naming it", key, v, err)
			}
		}
	}
	// Every invalid setting is reported at once, not only the first.
	t.Setenv("R_INT", "x")
	t.Setenv("R_BOOL", "maybe")
	var all env.Reader
	all.Int("R_INT", 1, 2)
	all.Bool("R_BOOL", false)
	if err := all.Err(); err == nil || !strings.Contains(err.Error(), "R_INT") ||
		!strings.Contains(err.Error(), "R_BOOL") {
		t.Fatalf("Err = %v, want both", err)
	}
}
