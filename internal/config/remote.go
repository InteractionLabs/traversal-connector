package config

import (
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"
)

func validateRemoteConfig(cfg Config) error {
	if cfg.ConfigEndpoint == "" {
		return nil
	}
	if cfg.ConfigRefreshInterval <= 0 || cfg.ConfigRefreshInterval > 24*time.Hour {
		return errors.New("TRAVERSAL_CONFIG_REFRESH_INTERVAL must be in (0, 24h]")
	}
	controller, err := url.Parse(cfg.TraversalControllerURL)
	if err != nil {
		return errors.New("invalid controller URL")
	}
	endpoint, err := url.Parse(cfg.ConfigEndpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" ||
		endpoint.ForceQuery ||
		endpoint.Fragment != "" {
		return errors.New(
			"TRAVERSAL_CONFIG_ENDPOINT must be an absolute URL without credentials, query or fragment",
		)
	}
	// Config must reuse the controller origin, TLS identity and socket/proxy
	// routing. In particular, never send the client certificate to another host.
	originPort := func(u *url.URL) string {
		if port := u.Port(); port != "" {
			return port
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	if endpoint.Scheme != controller.Scheme || endpoint.Hostname() != controller.Hostname() ||
		originPort(endpoint) != originPort(controller) {
		return errors.New(
			"TRAVERSAL_CONFIG_ENDPOINT must use the controller's scheme, hostname and port",
		)
	}
	id, err := uuid.Parse(cfg.ConnectorID)
	if err != nil || id.String() != cfg.ConnectorID {
		return errors.New("OTA config requires a canonical lowercase connector UUID")
	}
	return nil
}

// ConfigURL appends the connector ID to the configured endpoint, not an org ID:
// the gateway derives organization authorization from the mTLS certificate.
func (cfg Config) ConfigURL() (string, error) {
	return url.JoinPath(cfg.ConfigEndpoint, cfg.ConnectorID)
}
