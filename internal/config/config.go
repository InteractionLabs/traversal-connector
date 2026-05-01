package config

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/joho/godotenv"

	"github.com/InteractionLabs/traversal-connector/internal/env"
)

const (
	// Default configuration values.
	defaultMaxTunnelsAllowed     = 2
	defaultBodySizeMB            = 32
	defaultHTTPPort              = "8080"
	defaultMaxConcurrentRequests = 10
	defaultUpstreamTLSVerify     = true
	// pemPrefix is used to detect raw PEM content in certificate values.
	pemPrefix = "-----BEGIN"
	// Default timeout and interval durations.
	defaultReconnectInterval       = 5 * time.Second
	defaultMaxBackoffDelay         = 60 * time.Second
	defaultRequestTimeout          = 60 * time.Second
	defaultRedactionReloadInterval = 10 * time.Second
)

// Config holds all configuration for the Traversal Connector service.
type Config struct {
	// HTTPPort is the HTTP server port for health/readiness endpoints.
	HTTPPort string
	// TraversalControllerURL is the ConnectRPC URL of the Traversal control plane
	// to connect to. Required.
	TraversalControllerURL string
	// EnvName is the customer's environment name.
	EnvName string
	// EnvLevel is the deployment level (production or development).
	// Container image builds bake in "production"; falls back to "development"
	// when ENV_LEVEL is unset.
	EnvLevel env.EnvLevel
	// MaxTunnelsAllowed is the maximum number of concurrent gRPC
	// tunnels this traversal connector creates.
	MaxTunnelsAllowed int
	// ReconnectInterval is the interval for periodic connection rebalancing,
	// distributing tunnels across available Traversal control plane pods.
	ReconnectInterval time.Duration
	// MaxBackoffDelay is the maximum delay cap for exponential backoff on
	// reconnection attempts.
	MaxBackoffDelay time.Duration
	// RequestTimeout is the timeout for individual upstream HTTP requests
	// executed within the customer network.
	RequestTimeout time.Duration
	// MaxRequestBodySizeMB is the maximum size (in MB) allowed for HTTP
	// request bodies sent upstream.
	MaxRequestBodySizeMB int64
	// InternetProxyURL is the optional HTTP forward proxy URL used for any
	// connector-initiated egress to the Traversal SaaS — both the bidi
	// control-plane tunnel and OTLP telemetry export. Read from
	// INTERNET_PROXY_URL (e.g. "http://proxy.example.com:3128"). When set,
	// the controller URL must use https:// because HTTP/2 over a proxy
	// requires TLS. When unset, the connector dials its destinations
	// directly (h2c for the controller; default OTLP transport for telemetry).
	InternetProxyURL *string
	// TLSCert is the optional client TLS certificate PEM content
	// for mTLS to the Traversal control plane. Read from TLS_CERT_BASE64;
	// may be provided as raw PEM or base64-encoded PEM.
	TLSCert *string
	// TLSKey is the optional client TLS private key PEM content
	// for mTLS to the Traversal control plane. Read from TLS_KEY_BASE64;
	// may be provided as raw PEM or base64-encoded PEM.
	TLSKey *string
	// TLSCA is the optional CA certificate PEM content for server
	// certificate verification. Read from TLS_CA_BASE64;
	// may be provided as raw PEM or base64-encoded PEM.
	TLSCA *string
	// TLSServerName is the expected server name for TLS verification
	// when connecting to the Traversal control plane.
	TLSServerName string
	// OTELServiceName is the OpenTelemetry service name reported on traces,
	// metrics, and logs.
	OTELServiceName string
	// OTLPMetricsEndpoint is the OTLP endpoint for metrics export.
	// Supports full URLs (https://host/path) and bare host:port.
	// Empty means metrics export is skipped.
	OTLPMetricsEndpoint string
	// OTLPTracesEndpoint is the OTLP endpoint for traces export.
	// Supports full URLs (https://host/path) and bare host:port.
	// Empty means traces export is skipped.
	OTLPTracesEndpoint string
	// OTLPLogsEndpoint is the OTLP endpoint for logs export.
	// Supports full URLs (https://host/path) and bare host:port.
	// Empty means OTLP log export is skipped (stdout-only).
	OTLPLogsEndpoint string
	// OTLPProtocol selects the OTLP exporter transport.
	// "grpc" or "http/protobuf" → gRPC; "http/json" or "" → HTTP.
	OTLPProtocol string
	// MaxConcurrentRequests is the maximum number of concurrent HTTP requests
	// this traversal connector can handle per tunnel when multiplexing is active.
	MaxConcurrentRequests int
	// UpstreamTLSVerify controls whether TLS certificates are validated when
	// making HTTPS requests to upstream observability platforms.
	// When true, certificates must be valid and signed by a trusted CA.
	// When false, self-signed certificates are accepted.
	UpstreamTLSVerify bool
	// UpstreamTLSCA is the optional CA certificate PEM content for validating
	// upstream observability platform certificates. Read from UPSTREAM_TLS_CA_BASE64;
	// may be provided as raw PEM or base64-encoded PEM.
	// When set with UpstreamTLSVerify=true, only certificates signed by this CA are accepted.
	UpstreamTLSCA *string
	// RedactionRulesFile is the optional path to a TOML file containing redaction
	// rules applied to all upstream response bodies before they leave the customer
	// network. Read from REDACTION_RULES_FILE. When unset, no redaction is applied.
	RedactionRulesFile *string
	// RedactionReloadInterval is how often the redaction rules file is checked for
	// changes. Read from REDACTION_RELOAD_INTERVAL. Defaults to 10s.
	RedactionReloadInterval time.Duration
}

// Load reads configuration from environment variables and returns a Config
// with defaults applied for any unset values. Returns an error if required
// configuration is missing.
func Load() (Config, error) {
	// If ENV_FILE is set, load KEY=value pairs from that path into the process
	// environment. Useful for deployments that inject secrets as a dotenv-
	// formatted file (e.g. Vault Agent writing to a mounted path).
	if envFile := env.GetEnvOptionalString("ENV_FILE"); envFile != nil {
		if err := godotenv.Load(*envFile); err != nil {
			return Config{}, fmt.Errorf("load ENV_FILE %s: %w", *envFile, err)
		}
	}

	// Best-effort load of ./.env for local development. Missing file is fine.
	if err := godotenv.Load(); err != nil {
		slog.Debug("no ./.env file loaded", "error", err)
	}

	envName := env.GetEnvOptionalString("ENV_NAME")
	if envName == nil {
		return Config{}, errors.New("ENV_NAME is required")
	}

	traversalControllerURL := env.GetEnvOptionalString("TRAVERSAL_CONTROLLER_URL")
	if traversalControllerURL == nil {
		return Config{}, errors.New("TRAVERSAL_CONTROLLER_URL is required")
	}

	cfg := Config{
		HTTPPort:               env.GetEnvString("HTTP_PORT", defaultHTTPPort),
		TraversalControllerURL: *traversalControllerURL,
		EnvName:                *envName,
		EnvLevel: env.EnvLevel(
			env.GetEnvString("ENV_LEVEL", string(env.EnvLevelDevelopment)),
		),
		MaxTunnelsAllowed: env.GetEnvInt("MAX_TUNNELS_ALLOWED", defaultMaxTunnelsAllowed),
		ReconnectInterval: env.GetEnvDuration("RECONNECT_INTERVAL", defaultReconnectInterval),
		MaxBackoffDelay:   env.GetEnvDuration("MAX_BACKOFF_DELAY", defaultMaxBackoffDelay),
		RequestTimeout:    env.GetEnvDuration("REQUEST_TIMEOUT", defaultRequestTimeout),
		MaxRequestBodySizeMB: env.GetEnvInt64(
			"MAX_REQUEST_BODY_SIZE_MB",
			defaultBodySizeMB,
		),
		InternetProxyURL: env.GetEnvOptionalString("INTERNET_PROXY_URL"),
		TLSCert:          decodeCertificate(env.GetEnvOptionalString("TLS_CERT_BASE64")),
		TLSKey:           decodeCertificate(env.GetEnvOptionalString("TLS_KEY_BASE64")),
		TLSCA:            decodeCertificate(env.GetEnvOptionalString("TLS_CA_BASE64")),
		TLSServerName:    env.GetEnvString("TLS_SERVER_NAME", ""),
		OTELServiceName:  env.GetEnvString("OTEL_SERVICE_NAME", "traversal-connector"),
		OTLPMetricsEndpoint: env.GetEnvString(
			"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "",
		),
		OTLPTracesEndpoint: env.GetEnvString(
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "",
		),
		OTLPLogsEndpoint: env.GetEnvString(
			"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "",
		),
		OTLPProtocol: env.GetEnvString(
			"OTEL_EXPORTER_OTLP_PROTOCOL", "",
		),
		MaxConcurrentRequests: env.GetEnvInt(
			"MAX_CONCURRENT_REQUESTS",
			defaultMaxConcurrentRequests,
		),
		UpstreamTLSVerify: env.GetEnvBool("UPSTREAM_TLS_VERIFY", defaultUpstreamTLSVerify),
		UpstreamTLSCA: decodeCertificate(
			env.GetEnvOptionalString("UPSTREAM_TLS_CA_BASE64"),
		),
		RedactionRulesFile: env.GetEnvOptionalString("REDACTION_RULES_FILE"),
		RedactionReloadInterval: env.GetEnvDuration(
			"REDACTION_RELOAD_INTERVAL",
			defaultRedactionReloadInterval,
		),
	}

	if err := validateControllerConnection(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// validateControllerConnection enforces the controller-URL / TLS rules so
// misconfigurations fail at startup rather than after the connector has
// entered the reconnect-with-backoff loop. The rules:
//
//   - https:// requires both TLS_CERT_BASE64 and TLS_KEY_BASE64 (mTLS is
//     mandatory for production deployments).
//   - http:// is rejected when ENV_LEVEL=production.
//   - Other schemes are rejected.
//
// When mTLS material is configured but the URL is http://, the certs would
// silently be ignored; that case is allowed but logs a WARN so the operator
// notices.
func validateControllerConnection(cfg Config) error {
	u, err := url.Parse(cfg.TraversalControllerURL)
	if err != nil {
		return fmt.Errorf("invalid TRAVERSAL_CONTROLLER_URL: %w", err)
	}

	switch u.Scheme {
	case "https":
		if cfg.TLSCert == nil || cfg.TLSKey == nil {
			return errors.New(
				"TLS_CERT_BASE64 and TLS_KEY_BASE64 are required when " +
					"TRAVERSAL_CONTROLLER_URL uses https:// (mTLS is required)",
			)
		}
		if _, err := tls.X509KeyPair(
			[]byte(*cfg.TLSCert), []byte(*cfg.TLSKey),
		); err != nil {
			return fmt.Errorf("failed to parse client TLS certificate: %w", err)
		}
	case "http":
		if !cfg.EnvLevel.IsDev() {
			return errors.New(
				"http:// TRAVERSAL_CONTROLLER_URL is not allowed when " +
					"ENV_LEVEL=production; use https:// with " +
					"TLS_CERT_BASE64 / TLS_KEY_BASE64",
			)
		}
		if cfg.TLSCert != nil || cfg.TLSKey != nil {
			slog.Warn(
				"TLS client cert is configured but " +
					"TRAVERSAL_CONTROLLER_URL uses http://; " +
					"cert will be ignored",
			)
		}
	default:
		return fmt.Errorf(
			"TRAVERSAL_CONTROLLER_URL has unsupported scheme %q; "+
				"expected http:// or https://",
			u.Scheme,
		)
	}
	return nil
}

// decodeCertificate attempts to decode a base64-encoded certificate.
// If the input is nil, it returns nil.
// If the input looks like PEM content (starts with "-----BEGIN"), it returns the input as-is.
// Otherwise, it attempts to decode the input as base64.
func decodeCertificate(encoded *string) *string {
	if encoded == nil {
		return nil
	}

	// If it already looks like PEM content, return as-is
	if strings.HasPrefix(*encoded, pemPrefix) {
		return encoded
	}

	// Attempt to decode as base64
	decoded, err := base64.StdEncoding.DecodeString(*encoded)
	if err != nil {
		slog.Warn("failed to decode base64 certificate, using as-is", "error", err)
		return encoded
	}

	decodedStr := string(decoded)
	return &decodedStr
}
