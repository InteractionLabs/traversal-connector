package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadRedactionSource(t *testing.T) {
	for _, tc := range []struct {
		name, file, ota, interval, wantErr string
		wantInterval                       time.Duration
	}{
		{name: "disabled", wantInterval: 10 * time.Second},
		{name: "local", file: "/rules.toml", wantInterval: 10 * time.Second},
		{name: "local explicit OTA off", file: "/rules.toml", ota: "false", wantInterval: 10 * time.Second},
		{name: "local custom interval", file: "/rules.toml", interval: "2s", wantInterval: 2 * time.Second},
		{name: "remote", ota: "true", wantInterval: 10 * time.Second},
		{name: "both", file: "/rules.toml", ota: "true", wantErr: "mutually exclusive"},
		{name: "zero interval", file: "/rules.toml", interval: "0s", wantErr: "REDACTION_RELOAD_INTERVAL"},
		{name: "negative interval", file: "/rules.toml", interval: "-1s", wantErr: "REDACTION_RELOAD_INTERVAL"},
		{name: "malformed interval", file: "/rules.toml", interval: "typo", wantErr: "REDACTION_RELOAD_INTERVAL"},
		{name: "invalid OTA flag", file: "/rules.toml", ota: "typo", wantErr: "TRAVERSAL_CONFIG_ENABLED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ENV_LEVEL", "development")
			t.Setenv("ENV_NAME", "test")
			t.Setenv("TRAVERSAL_CONTROLLER_URL", "http://localhost:9080")
			// Local files do not require a canonical UUID or valid OTA polling interval.
			id := "connector-1"
			if tc.ota == "true" {
				id = configConnectorID
			}
			t.Setenv("TRAVERSAL_CONNECTOR_ID", id)
			t.Setenv("REDACTION_RULES_FILE", tc.file)
			t.Setenv("REDACTION_RELOAD_INTERVAL", tc.interval)
			t.Setenv("TRAVERSAL_CONFIG_ENABLED", tc.ota)
			t.Setenv("TRAVERSAL_CONFIG_ENDPOINT", "")
			t.Setenv("TRAVERSAL_CONFIG_REFRESH_INTERVAL", "30s")
			if tc.file != "" && tc.ota != "true" {
				t.Setenv("TRAVERSAL_CONFIG_REFRESH_INTERVAL", "-1s")
			}
			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected %s, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ConfigEnabled != (tc.ota == "true") ||
				cfg.RedactionReloadInterval != tc.wantInterval {
				t.Fatalf(
					"unexpected source settings: OTA=%v interval=%v",
					cfg.ConfigEnabled,
					cfg.RedactionReloadInterval,
				)
			}
			if tc.file == "" {
				if cfg.RedactionRulesFile != nil {
					t.Fatal("local file unexpectedly enabled")
				}
			} else if cfg.RedactionRulesFile == nil || *cfg.RedactionRulesFile != tc.file {
				t.Fatal("local file not configured")
			}
		})
	}
}
