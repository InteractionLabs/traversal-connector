package env

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestGetEnvString(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		value      string
		defaultVal string
		expected   string
	}{
		{"returns env value", "TEST_STR", "hello", "default", "hello"},
		{"returns default when empty", "TEST_STR", "", "default", "default"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv(tt.key)
			if tt.value != "" {
				os.Setenv(tt.key, tt.value)
			}
			defer os.Unsetenv(tt.key)

			got := GetEnvString(tt.key, tt.defaultVal)
			if diff := cmp.Diff(tt.expected, got); diff != "" {
				t.Errorf("GetEnvString() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		value      string
		defaultVal int
		expected   int
	}{
		{"valid int", "TEST_INT", "42", 10, 42},
		{"empty value", "TEST_INT", "", 10, 10},
		{"invalid int", "TEST_INT", "not-a-number", 10, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv(tt.key)
			if tt.value != "" {
				os.Setenv(tt.key, tt.value)
			}
			defer os.Unsetenv(tt.key)

			got := GetEnvInt(tt.key, tt.defaultVal)
			if diff := cmp.Diff(tt.expected, got); diff != "" {
				t.Errorf("GetEnvInt() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetEnvInt64(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		value      string
		defaultVal int64
		expected   int64
	}{
		{"valid int64", "TEST_INT64", "9223372036854775807", 100, 9223372036854775807},
		{"empty value", "TEST_INT64", "", 100, 100},
		{"invalid int64", "TEST_INT64", "not-a-number", 100, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv(tt.key)
			if tt.value != "" {
				os.Setenv(tt.key, tt.value)
			}
			defer os.Unsetenv(tt.key)

			got := GetEnvInt64(tt.key, tt.defaultVal)
			if diff := cmp.Diff(tt.expected, got); diff != "" {
				t.Errorf("GetEnvInt64() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetEnvDuration(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		value      string
		defaultVal time.Duration
		expected   time.Duration
	}{
		{"valid duration", "TEST_DURATION", "5m", 1 * time.Second, 5 * time.Minute},
		{"empty value", "TEST_DURATION", "", 1 * time.Second, 1 * time.Second},
		{"invalid duration", "TEST_DURATION", "invalid", 1 * time.Second, 1 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv(tt.key)
			if tt.value != "" {
				os.Setenv(tt.key, tt.value)
			}
			defer os.Unsetenv(tt.key)

			got := GetEnvDuration(tt.key, tt.defaultVal)
			if diff := cmp.Diff(tt.expected, got); diff != "" {
				t.Errorf("GetEnvDuration() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		value      string
		defaultVal bool
		expected   bool
	}{
		{"true string", "TEST_BOOL", "true", false, true},
		{"TRUE string", "TEST_BOOL", "TRUE", false, true},
		{"1 string", "TEST_BOOL", "1", false, true},
		{"false string", "TEST_BOOL", "false", true, false},
		{"FALSE string", "TEST_BOOL", "FALSE", true, false},
		{"0 string", "TEST_BOOL", "0", true, false},
		{"empty returns default true", "TEST_BOOL", "", true, true},
		{"empty returns default false", "TEST_BOOL", "", false, false},
		{"invalid returns default", "TEST_BOOL", "not-a-bool", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv(tt.key)
			if tt.value != "" {
				os.Setenv(tt.key, tt.value)
			}
			defer os.Unsetenv(tt.key)

			got := GetEnvBool(tt.key, tt.defaultVal)
			if diff := cmp.Diff(tt.expected, got); diff != "" {
				t.Errorf("GetEnvBool() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetEnvOptionalString(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    string
		expected *string
	}{
		{"returns pointer when set", "TEST_OPT", "value", ptrStr("value")},
		{"returns nil when empty", "TEST_OPT", "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv(tt.key)
			if tt.value != "" {
				os.Setenv(tt.key, tt.value)
			}
			defer os.Unsetenv(tt.key)

			got := GetEnvOptionalString(tt.key)
			if diff := cmp.Diff(tt.expected, got); diff != "" {
				t.Errorf("GetEnvOptionalString() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func ptrStr(s string) *string {
	return &s
}

func TestEnvLevel_IsDev(t *testing.T) {
	want := map[EnvLevel]bool{
		EnvLevelDevelopment: true,
		EnvLevelProduction:  false,
		EnvLevel(""):        false,
		EnvLevel("unknown"): false,
	}
	for level, expected := range want {
		t.Run(string(level), func(t *testing.T) {
			if got := level.IsDev(); got != expected {
				t.Errorf("(%q).IsDev() = %v, want %v",
					level, got, expected)
			}
		})
	}
}

func TestEnvLevelConstants(t *testing.T) {
	// The string values are a stable contract: the traversal-connector Dockerfile
	// bakes "ENV_LEVEL=production" into the production image, so renaming
	// either constant's value silently breaks that guarantee.
	if EnvLevelProduction != "production" {
		t.Errorf("EnvLevelProduction = %q, want %q",
			EnvLevelProduction, "production")
	}
	if EnvLevelDevelopment != "development" {
		t.Errorf("EnvLevelDevelopment = %q, want %q",
			EnvLevelDevelopment, "development")
	}
}
