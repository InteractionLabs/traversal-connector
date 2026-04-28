package config

import (
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/InteractionLabs/traversal-connector/internal/env"
)

func ptrTo[T any](v T) *T { return &v }

func TestLoad(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected Config
	}{
		{
			name: "default values",
			envVars: map[string]string{
				"ENV_NAME":                 "test",
				"TRAVERSAL_CONTROLLER_URL": "http://localhost:9080",
			},
			expected: Config{
				HTTPPort:               "8080",
				TraversalControllerURL: "http://localhost:9080",
				EnvName:                "test",
				EnvLevel:               env.EnvLevelDevelopment,
				MaxTunnelsAllowed:      2,
				ReconnectInterval:      5 * time.Second,
				MaxBackoffDelay:        60 * time.Second,
				RequestTimeout:         60 * time.Second,
				MaxRequestBodySizeMB:   32,
				TLSCert:                nil,
				TLSKey:                 nil,
				TLSServerName:          "",
				OTELServiceName:        "traversal-connector",
				MaxConcurrentRequests:  10,
				UpstreamTLSVerify:      true,
			},
		},
		{
			name: "custom values",
			envVars: map[string]string{
				"TRAVERSAL_CONTROLLER_URL":            "https://controller.example.com:9080",
				"ENV_NAME":                            "production",
				"ENV_LEVEL":                           "production",
				"MAX_TUNNELS_ALLOWED":                 "10",
				"RECONNECT_INTERVAL":                  "10m",
				"MAX_BACKOFF_DELAY":                   "120s",
				"REQUEST_TIMEOUT":                     "25s",
				"MAX_REQUEST_BODY_SIZE_MB":            "16",
				"TLS_CERT_BASE64":                     "/path/to/cert.pem",
				"TLS_KEY_BASE64":                      "/path/to/key.pem",
				"TLS_SERVER_NAME":                     "controller.example.com",
				"OTEL_SERVICE_NAME":                   "custom-traversal-connector",
				"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "localhost:4317",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":  "localhost:4317",
				"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":    "localhost:4317",
				"OTEL_EXPORTER_OTLP_PROTOCOL":         "grpc",
			},
			expected: Config{
				HTTPPort:               "8080",
				TraversalControllerURL: "https://controller.example.com:9080",
				EnvName:                "production",
				EnvLevel:               env.EnvLevelProduction,
				MaxTunnelsAllowed:      10,
				ReconnectInterval:      10 * time.Minute,
				MaxBackoffDelay:        120 * time.Second,
				RequestTimeout:         25 * time.Second,
				MaxRequestBodySizeMB:   16,
				TLSCert:                ptrTo("/path/to/cert.pem"),
				TLSKey:                 ptrTo("/path/to/key.pem"),
				TLSServerName:          "controller.example.com",
				OTELServiceName:        "custom-traversal-connector",
				OTLPMetricsEndpoint:    "localhost:4317",
				OTLPTracesEndpoint:     "localhost:4317",
				OTLPLogsEndpoint:       "localhost:4317",
				OTLPProtocol:           "grpc",
				MaxConcurrentRequests:  10,
				UpstreamTLSVerify:      true,
			},
		},
		{
			name: "staging environment",
			envVars: map[string]string{
				"ENV_NAME":                 "staging",
				"TRAVERSAL_CONTROLLER_URL": "http://localhost:9080",
			},
			expected: Config{
				HTTPPort:               "8080",
				TraversalControllerURL: "http://localhost:9080",
				EnvName:                "staging",
				EnvLevel:               env.EnvLevelDevelopment,
				MaxTunnelsAllowed:      2,
				ReconnectInterval:      5 * time.Second,
				MaxBackoffDelay:        60 * time.Second,
				RequestTimeout:         60 * time.Second,
				MaxRequestBodySizeMB:   32,
				TLSCert:                nil,
				TLSKey:                 nil,
				TLSServerName:          "",
				OTELServiceName:        "traversal-connector",
				MaxConcurrentRequests:  10,
				UpstreamTLSVerify:      true,
			},
		},
		{
			name: "invalid duration falls back to default",
			envVars: map[string]string{
				"ENV_NAME":                 "test",
				"TRAVERSAL_CONTROLLER_URL": "http://localhost:9080",
				"RECONNECT_INTERVAL":       "invalid",
				"MAX_BACKOFF_DELAY":        "also-invalid",
				"REQUEST_TIMEOUT":          "nope",
			},
			expected: Config{
				HTTPPort:               "8080",
				TraversalControllerURL: "http://localhost:9080",
				EnvName:                "test",
				EnvLevel:               env.EnvLevelDevelopment,
				MaxTunnelsAllowed:      2,
				ReconnectInterval:      5 * time.Second,
				MaxBackoffDelay:        60 * time.Second,
				RequestTimeout:         60 * time.Second,
				MaxRequestBodySizeMB:   32,
				TLSCert:                nil,
				TLSKey:                 nil,
				TLSServerName:          "",
				OTELServiceName:        "traversal-connector",
				MaxConcurrentRequests:  10,
				UpstreamTLSVerify:      true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv()

			for key, value := range tt.envVars {
				_ = os.Setenv(key, value)
			}
			defer clearEnv()

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() returned error: %v", err)
			}

			if diff := cmp.Diff(tt.expected, cfg, cmp.AllowUnexported(Config{})); diff != "" {
				t.Errorf("Load() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLoad_RequiresEnvName(t *testing.T) {
	clearEnv()
	defer clearEnv()

	if _, err := Load(); err == nil {
		t.Fatal("Load() returned nil error when ENV_NAME is unset; expected an error")
	}
}

func TestLoad_RequiresTraversalControllerURL(t *testing.T) {
	clearEnv()
	defer clearEnv()

	_ = os.Setenv("ENV_NAME", "test")

	if _, err := Load(); err == nil {
		t.Fatal(
			"Load() returned nil error when TRAVERSAL_CONTROLLER_URL is unset; expected an error",
		)
	}
}

func TestLoad_EnvFileMissing(t *testing.T) {
	clearEnv()
	defer clearEnv()

	_ = os.Setenv("ENV_NAME", "test")
	_ = os.Setenv("ENV_FILE", "/does/not/exist")

	if _, err := Load(); err == nil {
		t.Fatal(
			"Load() returned nil error when ENV_FILE points at a missing path; expected an error",
		)
	}
}

func TestLoad_EnvFilePopulatesEnv(t *testing.T) {
	clearEnv()
	defer clearEnv()

	tmp := t.TempDir() + "/secrets.env"
	envFileContent := "ENV_NAME=from-file\nTRAVERSAL_CONTROLLER_URL=http://localhost:9080\n"
	if err := os.WriteFile(tmp, []byte(envFileContent), 0o600); err != nil {
		t.Fatalf("write temp env file: %v", err)
	}
	_ = os.Setenv("ENV_FILE", tmp)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.EnvName != "from-file" {
		t.Errorf("EnvName = %q, want %q", cfg.EnvName, "from-file")
	}
}

func TestDecodeCertificate(t *testing.T) {
	pemCert := "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----"
	pemKey := "-----BEGIN EC PRIVATE KEY-----\nMIIByyy\n-----END EC PRIVATE KEY-----" //nolint:gosec // test fixture, not a real key
	nonPEM := "some-plain-value"

	b64Cert := base64.StdEncoding.EncodeToString([]byte(pemCert))
	b64Key := base64.StdEncoding.EncodeToString([]byte(pemKey))

	tests := []struct {
		name     string
		input    *string
		expected *string
	}{
		{
			name:     "nil input returns nil",
			input:    nil,
			expected: nil,
		},
		{
			name:     "raw PEM cert is returned as-is",
			input:    ptrTo(pemCert),
			expected: ptrTo(pemCert),
		},
		{
			name:     "raw PEM key is returned as-is",
			input:    ptrTo(pemKey),
			expected: ptrTo(pemKey),
		},
		{
			name:     "base64-encoded PEM cert is decoded",
			input:    ptrTo(b64Cert),
			expected: ptrTo(pemCert),
		},
		{
			name:     "base64-encoded PEM key is decoded",
			input:    ptrTo(b64Key),
			expected: ptrTo(pemKey),
		},
		{
			name:     "non-PEM non-base64 value is returned as-is",
			input:    ptrTo(nonPEM),
			expected: ptrTo(nonPEM),
		},
		{
			name:     "invalid base64 is returned as-is",
			input:    ptrTo("not!valid!base64!!!"),
			expected: ptrTo("not!valid!base64!!!"),
		},
		{
			name:     "empty string is returned as-is",
			input:    ptrTo(""),
			expected: ptrTo(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeCertificate(tt.input)

			if diff := cmp.Diff(tt.expected, got); diff != "" {
				t.Errorf("decodeCertificate() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func clearEnv() {
	envVars := []string{
		"HTTP_PORT", "TRAVERSAL_CONTROLLER_URL", "ENV_NAME", "ENV_LEVEL", "ENV_FILE", "MAX_TUNNELS_ALLOWED",
		"RECONNECT_INTERVAL", "MAX_BACKOFF_DELAY", "REQUEST_TIMEOUT",
		"MAX_REQUEST_BODY_SIZE_MB", "TLS_CERT_BASE64", "TLS_KEY_BASE64", "TLS_CA_BASE64",
		"TLS_SERVER_NAME", "OTEL_SERVICE_NAME",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_PROTOCOL",
		"UPSTREAM_TLS_VERIFY",
	}
	for _, key := range envVars {
		_ = os.Unsetenv(key)
	}
}
