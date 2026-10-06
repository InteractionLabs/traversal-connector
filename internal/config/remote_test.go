package config

import (
	"strings"
	"testing"
	"time"
)

const configConnectorID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

func TestConfigURLUsesOnlyControllerOrigin(t *testing.T) {
	for _, tc := range []struct{ controller, origin string }{
		{"https://edge.example.com", "https://edge.example.com"},
		{"https://edge.example.com:443/rpc", "https://edge.example.com:443"},
		{"https://edge.example.com/custom%2Fpath?ignored=1#fragment", "https://edge.example.com"},
		{"https://user:pass@edge.example.com/rpc", "https://edge.example.com"},
		{"http://localhost:9080/base", "http://localhost:9080"},
		{"https://[::1]:9443/base", "https://[::1]:9443"},
	} {
		cfg := Config{TraversalControllerURL: tc.controller, ConfigEnabled: true,
			ConnectorID: configConnectorID, ConfigRefreshInterval: time.Second}
		if err := validateRemoteConfig(cfg); err != nil {
			t.Fatal(err)
		}
		got, err := cfg.ConfigURL()
		if err != nil || got != tc.origin+"/v1/config/"+configConnectorID {
			t.Fatalf("URL: %q, %v", got, err)
		}
	}
}

func TestRemoteConfigInvalidIDAndInterval(t *testing.T) {
	cfg := Config{TraversalControllerURL: "https://edge.example.com",
		ConfigEnabled: true, ConnectorID: "../other",
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

func TestLoadRejectsConfigEndpointOverride(t *testing.T) {
	t.Setenv("ENV_LEVEL", "development")
	t.Setenv("ENV_NAME", "test")
	t.Setenv("TRAVERSAL_CONTROLLER_URL", "http://localhost:9080")
	t.Setenv("TRAVERSAL_CONNECTOR_ID", "connector-1")
	t.Setenv("TRAVERSAL_CONFIG_ENDPOINT", "https://other.example.com/config")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "TRAVERSAL_CONFIG_ENDPOINT") {
		t.Fatalf("expected endpoint override error, got %v", err)
	}
}

func TestLoadConfigEnableFlag(t *testing.T) {
	t.Setenv("ENV_LEVEL", "development")
	t.Setenv("ENV_NAME", "test")
	t.Setenv("TRAVERSAL_CONTROLLER_URL", "http://localhost:9080")
	t.Setenv("TRAVERSAL_CONNECTOR_ID", configConnectorID)
	t.Setenv("TRAVERSAL_CONFIG_ENABLED", "")
	cfg, err := Load()
	if err != nil || cfg.ConfigEnabled {
		t.Fatalf("polling should default off: %v", err)
	}
	t.Setenv("TRAVERSAL_CONFIG_ENABLED", "true")
	cfg, err = Load()
	if err != nil || !cfg.ConfigEnabled {
		t.Fatalf("polling should be enabled: %v", err)
	}
	t.Setenv("TRAVERSAL_CONFIG_ENABLED", "typo")
	if _, err = Load(); err == nil {
		t.Fatal("invalid enable flag silently disabled redaction")
	}
}
