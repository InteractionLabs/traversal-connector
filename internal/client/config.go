package client

import (
	"net/http"
	"time"

	"github.com/InteractionLabs/traversal-connector/internal/config"
)

// NewConfigHTTPClient shares controller mTLS, CA verification, explicit proxy
// and connect-to routing, without changing the long-lived tunnel's timeouts.
func NewConfigHTTPClient(cfg *config.Config) (*http.Client, error) {
	transport, err := newTransport(cfg)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}
