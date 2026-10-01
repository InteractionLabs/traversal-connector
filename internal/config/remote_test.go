package config

import (
	"strings"
	"testing"
	"time"
)

const configConnectorID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

func TestRemoteConfigSameOrigin(t *testing.T) {
	for _, endpoint := range []string{
		"https://edge.example.com/v1/config",
		"https://edge.example.com:443/v1/config",
	} {
		cfg := Config{TraversalControllerURL: "https://edge.example.com",
			ConfigEndpoint: endpoint, ConnectorID: configConnectorID, ConfigRefreshInterval: time.Second}
		if err := validateRemoteConfig(cfg); err != nil {
			t.Fatal(err)
		}
		got, err := cfg.ConfigURL()
		if err != nil || !strings.HasSuffix(got, "/v1/config/"+configConnectorID) {
			t.Fatalf("URL: %q, %v", got, err)
		}
	}
	for _, endpoint := range []string{
		"https://other.example.com/v1/config", "https://edge.example.com:8443/v1/config",
		"http://edge.example.com/v1/config", "/v1/config", "https://user@edge.example.com/v1/config",
		"https://edge.example.com/v1/config?token=1", "https://edge.example.com/v1/config#fragment",
	} {
		cfg := Config{TraversalControllerURL: "https://edge.example.com",
			ConfigEndpoint: endpoint, ConnectorID: configConnectorID, ConfigRefreshInterval: time.Second}
		if err := validateRemoteConfig(cfg); err == nil {
			t.Fatalf("accepted %s", endpoint)
		}
	}
}

func TestRemoteConfigInvalidIDAndInterval(t *testing.T) {
	cfg := Config{TraversalControllerURL: "https://edge.example.com",
		ConfigEndpoint: "https://edge.example.com/v1/config", ConnectorID: "../other",
		ConfigRefreshInterval: time.Second}
	if validateRemoteConfig(cfg) == nil {
		t.Fatal("accepted path traversal")
	}
	cfg.ConnectorID = strings.ToUpper(configConnectorID)
	if validateRemoteConfig(cfg) == nil {
		t.Fatal("accepted noncanonical UUID that would address a different S3 key")
	}
	cfg.ConnectorID = configConnectorID
	for _, interval := range []time.Duration{0, -time.Second, 25 * time.Hour} {
		cfg.ConfigRefreshInterval = interval
		if validateRemoteConfig(cfg) == nil {
			t.Fatal("accepted invalid interval")
		}
	}
}

func TestLoadRejectsDeprecatedRedactionSettings(t *testing.T) {
	t.Setenv("ENV_LEVEL", "development")
	t.Setenv("ENV_NAME", "test")
	t.Setenv("TRAVERSAL_CONTROLLER_URL", "http://localhost:9080")
	t.Setenv("TRAVERSAL_CONNECTOR_ID", "connector-1")
	for _, key := range []string{"REDACTION_RULES_FILE", "REDACTION_RELOAD_INTERVAL"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "legacy")
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("expected migration error for %s, got %v", key, err)
			}
		})
	}
}
