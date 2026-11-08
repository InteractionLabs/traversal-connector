package config

import (
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"
)

func validateRemoteConfig(cfg Config) error {
	if !cfg.ConfigEnabled && !cfg.TrustBootstrapEnabled {
		return nil
	}
	if cfg.ConfigEnabled && (cfg.ConfigRefreshInterval <= 0 || cfg.ConfigRefreshInterval > 24*time.Hour) {
		return errors.New("TRAVERSAL_CONFIG_REFRESH_INTERVAL must be in (0, 24h]")
	}
	id, err := uuid.Parse(cfg.ConnectorID)
	if err != nil || id.String() != cfg.ConnectorID {
		return errors.New("OTA config and trust bootstrap require a canonical lowercase connector UUID")
	}
	return nil
}

// ConfigURL keeps only the controller origin and uses the gateway's fixed path.
// Organization authorization comes from mTLS, never the URL.
func (cfg Config) ConfigURL() (string, error) {
	return cfg.controllerURL("/v1/config/")
}

// TrustURL keeps only the controller origin and uses the enrollment trust path.
func (cfg Config) TrustURL() (string, error) {
	return cfg.controllerURL("/v1/trust/")
}

func (cfg Config) controllerURL(prefix string) (string, error) {
	controller, err := url.Parse(cfg.TraversalControllerURL)
	if err != nil || controller.Hostname() == "" {
		return "", errors.New("invalid controller URL")
	}
	return (&url.URL{
		Scheme: controller.Scheme,
		Host:   controller.Host,
		Path:   prefix + cfg.ConnectorID,
	}).String(), nil
}
