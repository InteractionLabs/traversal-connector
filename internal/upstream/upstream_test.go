package upstream

import (
	"crypto/tls"
	"testing"

	"github.com/InteractionLabs/traversal-connector/internal/config"
)

// TestTrustTLS12Floor: the upstream TLS config refuses anything below TLS
// 1.2; 1.2 itself stays, since some customer servers speak nothing newer.
func TestTrustTLS12Floor(t *testing.T) {
	tlsCfg, err := trust(&config.Config{UpstreamTLSVerify: true})
	if err != nil {
		t.Fatalf("trust() error: %v", err)
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS 1.2 (%#x)", tlsCfg.MinVersion, tls.VersionTLS12)
	}
}
