package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/InteractionLabs/traversal-connector/internal/env"
)

func ptrTo[T any](v T) *T { return &v }

// generateTestKeyPair returns a freshly-generated self-signed cert and key
// as PEM strings. Used by tests that go through Load() with an https://
// controller URL, since validateControllerConnection calls tls.X509KeyPair.
func generateTestKeyPair(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, template, &priv.PublicKey, priv,
	)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: der},
	))
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER},
	))
	return certPEM, keyPEM
}

func TestLoad(t *testing.T) {
	certPEM, keyPEM := generateTestKeyPair(t)

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
				"TRAVERSAL_CONNECTOR_ID":   "connector-1",
			},
			expected: Config{
				HTTPPort:                     "8080",
				TraversalControllerURL:       "http://localhost:9080",
				EnvName:                      "test",
				EnvLevel:                     env.EnvLevelDevelopment,
				ConnectorID:                  "connector-1",
				MaxTunnelsAllowed:            2,
				ReconnectInterval:            5 * time.Second,
				MaxBackoffDelay:              60 * time.Second,
				RequestTimeout:               60 * time.Second,
				MaxRequestBodySizeMB:         32,
				MaxResponseBodySizeMB:        32,
				MaxDecodedResponseBodySizeMB: 256,
				TLSCert:                      nil,
				TLSKey:                       nil,
				OTELServiceName:              "traversal-connector",
				MaxConcurrentRequests:        10,
				UpstreamTLSVerify:            true,
				RedactionReloadInterval:      10 * time.Second,
			},
		},
		{
			name: "quoted connector id is trimmed",
			envVars: map[string]string{
				"ENV_NAME":                 "test",
				"TRAVERSAL_CONTROLLER_URL": "http://localhost:9080",
				"TRAVERSAL_CONNECTOR_ID":   `"connector-1"`,
			},
			expected: Config{
				HTTPPort:                     "8080",
				TraversalControllerURL:       "http://localhost:9080",
				EnvName:                      "test",
				EnvLevel:                     env.EnvLevelDevelopment,
				ConnectorID:                  "connector-1",
				MaxTunnelsAllowed:            2,
				ReconnectInterval:            5 * time.Second,
				MaxBackoffDelay:              60 * time.Second,
				RequestTimeout:               60 * time.Second,
				MaxRequestBodySizeMB:         32,
				MaxResponseBodySizeMB:        32,
				MaxDecodedResponseBodySizeMB: 256,
				TLSCert:                      nil,
				TLSKey:                       nil,
				OTELServiceName:              "traversal-connector",
				MaxConcurrentRequests:        10,
				UpstreamTLSVerify:            true,
				RedactionReloadInterval:      10 * time.Second,
			},
		},
		{
			name: "custom values",
			envVars: map[string]string{
				"TRAVERSAL_CONTROLLER_URL":            "https://controller.example.com:9080",
				"ENV_NAME":                            "production",
				"TRAVERSAL_CONNECTOR_ID":              "connector-prod",
				"ENV_LEVEL":                           "production",
				"MAX_TUNNELS_ALLOWED":                 "10",
				"RECONNECT_INTERVAL":                  "10m",
				"MAX_BACKOFF_DELAY":                   "120s",
				"REQUEST_TIMEOUT":                     "25s",
				"MAX_REQUEST_BODY_SIZE_MB":            "16",
				"MAX_RESPONSE_BODY_SIZE_MB":           "64",
				"MAX_DECODED_RESPONSE_BODY_SIZE_MB":   "512",
				"TLS_CERT_BASE64":                     certPEM,
				"TLS_KEY_BASE64":                      keyPEM,
				"OTEL_SERVICE_NAME":                   "custom-traversal-connector",
				"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "https://otlp.example.com:4317",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":  "https://otlp.example.com:4317",
				"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":    "https://otlp.example.com:4317",
				"OTEL_EXPORTER_OTLP_PROTOCOL":         "grpc",
			},
			expected: Config{
				HTTPPort:                     "8080",
				TraversalControllerURL:       "https://controller.example.com:9080",
				EnvName:                      "production",
				ConnectorID:                  "connector-prod",
				EnvLevel:                     env.EnvLevelProduction,
				MaxTunnelsAllowed:            10,
				ReconnectInterval:            10 * time.Minute,
				MaxBackoffDelay:              120 * time.Second,
				RequestTimeout:               25 * time.Second,
				MaxRequestBodySizeMB:         16,
				MaxResponseBodySizeMB:        64,
				MaxDecodedResponseBodySizeMB: 512,
				TLSCert:                      &certPEM,
				TLSKey:                       &keyPEM,
				OTELServiceName:              "custom-traversal-connector",
				OTLPMetricsEndpoint:          "https://otlp.example.com:4317",
				OTLPTracesEndpoint:           "https://otlp.example.com:4317",
				OTLPLogsEndpoint:             "https://otlp.example.com:4317",
				OTLPProtocol:                 "grpc",
				MaxConcurrentRequests:        10,
				UpstreamTLSVerify:            true,
				RedactionReloadInterval:      10 * time.Second,
			},
		},
		{
			name: "staging environment",
			envVars: map[string]string{
				"ENV_NAME":                 "staging",
				"TRAVERSAL_CONTROLLER_URL": "http://localhost:9080",
				"TRAVERSAL_CONNECTOR_ID":   "connector-staging",
			},
			expected: Config{
				HTTPPort:                     "8080",
				TraversalControllerURL:       "http://localhost:9080",
				EnvName:                      "staging",
				ConnectorID:                  "connector-staging",
				EnvLevel:                     env.EnvLevelDevelopment,
				MaxTunnelsAllowed:            2,
				ReconnectInterval:            5 * time.Second,
				MaxBackoffDelay:              60 * time.Second,
				RequestTimeout:               60 * time.Second,
				MaxRequestBodySizeMB:         32,
				MaxResponseBodySizeMB:        32,
				MaxDecodedResponseBodySizeMB: 256,
				TLSCert:                      nil,
				TLSKey:                       nil,
				OTELServiceName:              "traversal-connector",
				MaxConcurrentRequests:        10,
				UpstreamTLSVerify:            true,
				RedactionReloadInterval:      10 * time.Second,
			},
		},
		{
			name: "invalid duration falls back to default",
			envVars: map[string]string{
				"ENV_NAME":                 "test",
				"TRAVERSAL_CONTROLLER_URL": "http://localhost:9080",
				"TRAVERSAL_CONNECTOR_ID":   "connector-1",
				"RECONNECT_INTERVAL":       "invalid",
				"MAX_BACKOFF_DELAY":        "also-invalid",
				"REQUEST_TIMEOUT":          "nope",
			},
			expected: Config{
				HTTPPort:                     "8080",
				TraversalControllerURL:       "http://localhost:9080",
				EnvName:                      "test",
				ConnectorID:                  "connector-1",
				EnvLevel:                     env.EnvLevelDevelopment,
				MaxTunnelsAllowed:            2,
				ReconnectInterval:            5 * time.Second,
				MaxBackoffDelay:              60 * time.Second,
				RequestTimeout:               60 * time.Second,
				MaxRequestBodySizeMB:         32,
				MaxResponseBodySizeMB:        32,
				MaxDecodedResponseBodySizeMB: 256,
				TLSCert:                      nil,
				TLSKey:                       nil,
				OTELServiceName:              "traversal-connector",
				MaxConcurrentRequests:        10,
				UpstreamTLSVerify:            true,
				RedactionReloadInterval:      10 * time.Second,
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

func TestLoad_RequiresConnectorID(t *testing.T) {
	clearEnv()
	defer clearEnv()

	_ = os.Setenv("ENV_NAME", "test")
	_ = os.Setenv("TRAVERSAL_CONTROLLER_URL", "http://localhost:9080")

	if _, err := Load(); err == nil {
		t.Fatal(
			"Load() returned nil error when TRAVERSAL_CONNECTOR_ID is unset; expected an error",
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
	envFileContent := "ENV_NAME=from-file\nTRAVERSAL_CONTROLLER_URL=http://localhost:9080\nTRAVERSAL_CONNECTOR_ID=connector-1\n"
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

func TestLoad_RequiresMTLSForHTTPS(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
	}{
		{
			name: "https URL without cert or key",
			envVars: map[string]string{
				"ENV_NAME":                 "test",
				"TRAVERSAL_CONTROLLER_URL": "https://controller.example.com:9080",
				"TRAVERSAL_CONNECTOR_ID":   "connector-1",
			},
		},
		{
			name: "https URL with cert but no key",
			envVars: map[string]string{
				"ENV_NAME":                 "test",
				"TRAVERSAL_CONTROLLER_URL": "https://controller.example.com:9080",
				"TRAVERSAL_CONNECTOR_ID":   "connector-1",
				"TLS_CERT_BASE64":          "-----BEGIN CERTIFICATE-----\nXXX\n-----END CERTIFICATE-----",
			},
		},
		{
			name: "https URL with key but no cert",
			envVars: map[string]string{ //nolint:gosec // G101: test fixture, intentional fake key
				"ENV_NAME":                 "test",
				"TRAVERSAL_CONTROLLER_URL": "https://controller.example.com:9080",
				"TRAVERSAL_CONNECTOR_ID":   "connector-1",
				"TLS_KEY_BASE64":           "-----BEGIN EC PRIVATE KEY-----\nXXX\n-----END EC PRIVATE KEY-----",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv()
			defer clearEnv()
			for k, v := range tt.envVars {
				_ = os.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Fatal("Load() returned nil error; expected mTLS-required error")
			}
		})
	}
}

func TestLoad_RejectsMalformedCert(t *testing.T) {
	clearEnv()
	defer clearEnv()
	_ = os.Setenv("ENV_NAME", "test")
	_ = os.Setenv("TRAVERSAL_CONTROLLER_URL", "https://controller.example.com:9080")
	_ = os.Setenv("TRAVERSAL_CONNECTOR_ID", "connector-1")
	_ = os.Setenv("TLS_CERT_BASE64", "not a valid PEM")
	_ = os.Setenv("TLS_KEY_BASE64", "also not valid")

	if _, err := Load(); err == nil {
		t.Fatal("Load() returned nil error for malformed cert; expected parse error")
	}
}

func TestLoad_AcceptsHTTPInDev(t *testing.T) {
	hosts := []string{
		"localhost", "127.0.0.1", "host.docker.internal",
		"controller.example.com", "internal-test-controller.dev",
	}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			clearEnv()
			defer clearEnv()
			_ = os.Setenv("ENV_NAME", "test")
			_ = os.Setenv("TRAVERSAL_CONNECTOR_ID", "connector-1")
			_ = os.Setenv(
				"TRAVERSAL_CONTROLLER_URL",
				"http://"+host+":9080",
			)
			if _, err := Load(); err != nil {
				t.Fatalf("Load() returned error for %s: %v", host, err)
			}
		})
	}
}

func TestLoad_RejectsHTTPInProduction(t *testing.T) {
	hosts := []string{"localhost", "127.0.0.1", "controller.example.com"}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			clearEnv()
			defer clearEnv()
			_ = os.Setenv("ENV_NAME", "test")
			_ = os.Setenv("TRAVERSAL_CONNECTOR_ID", "connector-1")
			_ = os.Setenv("ENV_LEVEL", "production")
			_ = os.Setenv(
				"TRAVERSAL_CONTROLLER_URL",
				"http://"+host+":9080",
			)
			if _, err := Load(); err == nil {
				t.Fatalf(
					"Load() returned nil error for http://%s "+
						"with ENV_LEVEL=production",
					host,
				)
			}
		})
	}
}

func TestLoad_RejectsUnsupportedScheme(t *testing.T) {
	clearEnv()
	defer clearEnv()
	_ = os.Setenv("ENV_NAME", "test")
	_ = os.Setenv("TRAVERSAL_CONNECTOR_ID", "connector-1")
	_ = os.Setenv("TRAVERSAL_CONTROLLER_URL", "ftp://controller.example.com")

	if _, err := Load(); err == nil {
		t.Fatal("Load() returned nil error for unsupported scheme; expected error")
	}
}

// setProductionEnv sets the minimum environment for a production-level Load.
// ENV_LEVEL=production forces an https:// controller URL, which in turn requires
// mTLS material.
func setProductionEnv(t *testing.T, certPEM, keyPEM string) {
	t.Helper()
	_ = os.Setenv("ENV_NAME", "test")
	_ = os.Setenv("TRAVERSAL_CONNECTOR_ID", "connector-1")
	_ = os.Setenv("ENV_LEVEL", "production")
	_ = os.Setenv(
		"TRAVERSAL_CONTROLLER_URL", "https://controller.example.com:9080",
	)
	_ = os.Setenv("TLS_CERT_BASE64", certPEM)
	_ = os.Setenv("TLS_KEY_BASE64", keyPEM)
}

// setOTLPEndpoints points all three signals at one endpoint.
func setOTLPEndpoints(endpoint string) {
	_ = os.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", endpoint)
	_ = os.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", endpoint)
	_ = os.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", endpoint)
}

func TestLoad_RequiresEveryOTLPEndpointInProduction(t *testing.T) {
	certPEM, keyPEM := generateTestKeyPair(t)
	for _, missing := range []string{
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
	} {
		t.Run(missing, func(t *testing.T) {
			clearEnv()
			defer clearEnv()
			setProductionEnv(t, certPEM, keyPEM)
			setOTLPEndpoints("https://otlp.example.com:4317")
			_ = os.Unsetenv(missing)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load() returned nil error with %s unset", missing)
			}
			if !strings.Contains(err.Error(), missing) {
				t.Errorf("error %q does not name %s", err, missing)
			}
		})
	}
}

func TestLoad_RejectsUnusableOTLPEndpointInProduction(t *testing.T) {
	certPEM, keyPEM := generateTestKeyPair(t)
	tests := []struct {
		endpoint string
		// wantErrContains keeps each case on the branch it is meant to exercise:
		// asserting only "some error" lets a case drift onto another branch, or
		// pass because the surrounding environment broke instead.
		wantErrContains string
	}{
		// Cleartext on the wire.
		{"http://otlp.example.com:4317", "must be an https:// URL"},
		{"ftp://otlp.example.com:4317", "must be an https:// URL"},
		// Non-loopback host that merely reads as local.
		{"http://localhost.example.com:4318", "must be an https:// URL"},
		// Scheme-less: the exporters never negotiate TLS for these.
		{"otlp.example.com:4317", "must be an https:// URL including a host"},
		// Authority with a port but no host. Parses with a non-empty Host, and an
		// exporter would resolve it to localhost and drop every batch.
		{"https://:4317", "must be an https:// URL including a host"},
		{"https://", "must be an https:// URL including a host"},
		{"https://otlp.example.com:99999", "out-of-range port"},
	}
	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			clearEnv()
			defer clearEnv()
			setProductionEnv(t, certPEM, keyPEM)
			setOTLPEndpoints(tt.endpoint)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load() returned nil error for endpoint %q", tt.endpoint)
			}
			if !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf(
					"error %q does not contain %q", err, tt.wantErrContains,
				)
			}
			if !strings.Contains(err.Error(), "OTEL_EXPORTER_OTLP_") {
				t.Errorf("error %q does not name the offending variable", err)
			}
		})
	}
}

// A credential embedded in an endpoint must not reach the startup error, which
// is logged and may be shipped off-host.
func TestLoad_RedactsCredentialsInOTLPEndpointError(t *testing.T) {
	certPEM, keyPEM := generateTestKeyPair(t)
	clearEnv()
	defer clearEnv()
	setProductionEnv(t, certPEM, keyPEM)
	setOTLPEndpoints("http://user:supersecret@otlp.example.com:4317")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() returned nil error for a cleartext endpoint")
	}
	if strings.Contains(err.Error(), "supersecret") {
		t.Errorf("error leaks the endpoint credential: %q", err)
	}
}

// The colocated-forwarder shape: the connector ships OTLP over the pod loopback
// and the forwarder holds the mTLS identity for the egress.
func TestLoad_AcceptsLoopbackHTTPOTLPEndpointInProduction(t *testing.T) {
	certPEM, keyPEM := generateTestKeyPair(t)
	endpoints := []string{
		"http://127.0.0.1:4318/v1/metrics",
		"http://localhost:4318",
		"http://[::1]:4318",
		// Host names are case-insensitive and may carry the root dot.
		"http://LOCALHOST:4318",
		"http://localhost.:4318",
		// Anywhere in 127.0.0.0/8, and the IPv4-mapped IPv6 form.
		"http://127.9.9.9:4318",
		"http://[::ffff:127.0.0.1]:4318",
	}
	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			clearEnv()
			defer clearEnv()
			setProductionEnv(t, certPEM, keyPEM)
			setOTLPEndpoints(endpoint)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() returned error for endpoint %q: %v", endpoint, err)
			}
			if cfg.OTLPMetricsEndpoint != endpoint {
				t.Errorf(
					"OTLPMetricsEndpoint = %q, want %q",
					cfg.OTLPMetricsEndpoint, endpoint,
				)
			}
		})
	}
}

func TestLoad_AllowsMissingOTLPEndpointsInDev(t *testing.T) {
	clearEnv()
	defer clearEnv()
	_ = os.Setenv("ENV_NAME", "test")
	_ = os.Setenv("TRAVERSAL_CONNECTOR_ID", "connector-1")
	_ = os.Setenv("TRAVERSAL_CONTROLLER_URL", "http://localhost:9080")

	if _, err := Load(); err != nil {
		t.Fatalf("Load() returned error with no endpoints in dev: %v", err)
	}
}

func TestLoad_DisableTelemetryDropsConfiguredEndpoints(t *testing.T) {
	certPEM, keyPEM := generateTestKeyPair(t)
	clearEnv()
	defer clearEnv()
	setProductionEnv(t, certPEM, keyPEM)
	// Endpoints that would otherwise be rejected: the opt-out is absolute, so
	// they are dropped rather than validated.
	setOTLPEndpoints("http://otlp.example.com:4317")
	_ = os.Setenv("TRAVERSAL_DISABLE_TELEMETRY", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error with telemetry disabled: %v", err)
	}
	if !cfg.DisableTelemetry {
		t.Error("DisableTelemetry = false, want true")
	}
	for name, got := range map[string]string{
		"OTLPMetricsEndpoint": cfg.OTLPMetricsEndpoint,
		"OTLPTracesEndpoint":  cfg.OTLPTracesEndpoint,
		"OTLPLogsEndpoint":    cfg.OTLPLogsEndpoint,
	} {
		if got != "" {
			t.Errorf("%s = %q, want empty", name, got)
		}
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

func TestBuildClientTLSConfig(t *testing.T) {
	certPEM, keyPEM := generateTestKeyPair(t)
	caPEM, _ := generateTestKeyPair(t)

	t.Run("nil when no client cert/key", func(t *testing.T) {
		got, err := BuildClientTLSConfig(&Config{})
		if err != nil {
			t.Fatalf("BuildClientTLSConfig() error: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil config when certs absent, got %+v", got)
		}
	})

	t.Run("error on malformed cert", func(t *testing.T) {
		_, err := BuildClientTLSConfig(&Config{
			TLSCert: ptrTo("not a cert"),
			TLSKey:  ptrTo("not a key"),
		})
		if err == nil {
			t.Error("expected error for malformed cert, got nil")
		}
	})

	t.Run("CA populates RootCAs", func(t *testing.T) {
		withCA, err := BuildClientTLSConfig(&Config{
			TLSCert: ptrTo(certPEM),
			TLSKey:  ptrTo(keyPEM),
			TLSCA:   ptrTo(caPEM),
		})
		if err != nil {
			t.Fatalf("BuildClientTLSConfig() error: %v", err)
		}
		if withCA.RootCAs == nil {
			t.Error("RootCAs = nil, want populated pool from TLSCA")
		}

		withoutCA, err := BuildClientTLSConfig(&Config{
			TLSCert: ptrTo(certPEM),
			TLSKey:  ptrTo(keyPEM),
		})
		if err != nil {
			t.Fatalf("BuildClientTLSConfig() error: %v", err)
		}
		if withoutCA.RootCAs != nil {
			t.Error("RootCAs should be nil when TLSCA is unset (system roots)")
		}
	})
}

func clearEnv() {
	envVars := []string{
		"HTTP_PORT", "TRAVERSAL_CONTROLLER_URL", "TRAVERSAL_CONNECTOR_ID", "ENV_NAME", "ENV_LEVEL", "ENV_FILE", "MAX_TUNNELS_ALLOWED",
		"RECONNECT_INTERVAL", "MAX_BACKOFF_DELAY", "REQUEST_TIMEOUT",
		"MAX_REQUEST_BODY_SIZE_MB", "MAX_RESPONSE_BODY_SIZE_MB",
		"MAX_DECODED_RESPONSE_BODY_SIZE_MB",
		"TLS_CERT_BASE64", "TLS_KEY_BASE64", "TLS_CA_BASE64",
		"OTEL_SERVICE_NAME",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_PROTOCOL",
		"TRAVERSAL_DISABLE_TELEMETRY",
		"UPSTREAM_TLS_VERIFY",
	}
	for _, key := range envVars {
		_ = os.Unsetenv(key)
	}
}
