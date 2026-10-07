package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strconv"
	"strings"
	"testing"
	"time"
)

func publicKeyBlock(t *testing.T, kid string) (string, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{}
	if kid != "" {
		headers[keyIDHeader] = kid
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: headers, Bytes: der})),
		&key.PublicKey
}

func TestParseCapabilityKeys(t *testing.T) {
	current, currentKey := publicKeyBlock(t, "prod-current")
	next, nextKey := publicKeyBlock(t, "prod-next")
	keys, err := ParseCapabilityKeys([]byte(current + next))
	if err != nil {
		t.Fatal(err)
	}
	if !keys["prod-current"].Equal(currentKey) || !keys["prod-next"].Equal(nextKey) ||
		len(keys) != 2 {
		t.Fatalf("parsed %v", keys)
	}

	unnamed, _ := publicKeyBlock(t, "")
	for name, bundle := range map[string]string{
		"empty":          "",
		"missing kid":    unnamed,
		"duplicate kid":  current + current,
		"trailing data":  current + "garbage",
		"certificate":    "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
		"not a key body": "-----BEGIN PUBLIC KEY-----\nKey-ID: x\n\nAAAA\n-----END PUBLIC KEY-----\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCapabilityKeys([]byte(bundle)); err == nil {
				t.Fatal("accepted an invalid bundle")
			}
		})
	}
}

func TestLoadRawPipes(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		cfg, err := loadRawPipes()
		if err != nil || cfg.Enabled {
			t.Fatalf("got %+v, %v", cfg, err)
		}
	})
	t.Run("rejects unknown modes", func(t *testing.T) {
		t.Setenv("TRAVERSAL_RAW_PIPES", "on")
		if _, err := loadRawPipes(); err == nil {
			t.Fatal("accepted TRAVERSAL_RAW_PIPES=on")
		}
	})
	t.Run("enabled requires an issuer and keys", func(t *testing.T) {
		t.Setenv("TRAVERSAL_RAW_PIPES", "enabled")
		if _, err := loadRawPipes(); err == nil || !strings.Contains(err.Error(), "ISSUER") {
			t.Fatalf("missing issuer: %v", err)
		}
		t.Setenv("TRAVERSAL_CAPABILITY_ISSUER", "traversal-raw-tunnel/prod")
		if _, err := loadRawPipes(); err == nil || !strings.Contains(err.Error(), "KEYS") {
			t.Fatalf("missing keys: %v", err)
		}
	})
	t.Run("enabled", func(t *testing.T) {
		block, _ := publicKeyBlock(t, "prod-current")
		t.Setenv("TRAVERSAL_RAW_PIPES", "enabled")
		t.Setenv("TRAVERSAL_CAPABILITY_ISSUER", "traversal-raw-tunnel/prod")
		t.Setenv("TRAVERSAL_CAPABILITY_KEYS", block)
		t.Setenv("TRAVERSAL_RAW_PIPES_MAX", "50")
		cfg, err := loadRawPipes()
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Enabled || cfg.MaxPipes != 50 || cfg.CapabilityKeys["prod-current"] == nil ||
			cfg.Listen != rawPipesListen {
			t.Fatalf("got %+v", cfg)
		}
	})
	t.Run("tunnel count, with the older name as a fallback", func(t *testing.T) {
		block, _ := publicKeyBlock(t, "prod-current")
		t.Setenv("TRAVERSAL_RAW_PIPES", "enabled")
		t.Setenv("TRAVERSAL_CAPABILITY_ISSUER", "traversal-raw-tunnel/prod")
		t.Setenv("TRAVERSAL_CAPABILITY_KEYS", block)
		for _, c := range []struct {
			count, perReplica string
			want              int
		}{
			{"", "", defaultTunnelCount},
			{"", "3", 3},
			{"4", "3", 4},
		} {
			t.Setenv("TRAVERSAL_TUNNEL_COUNT", c.count)
			t.Setenv("TRAVERSAL_TUNNELS_PER_REPLICA", c.perReplica)
			cfg, err := loadRawPipes()
			if err != nil || cfg.TunnelCount != c.want {
				t.Fatalf("%+v: got %d, %v", c, cfg.TunnelCount, err)
			}
		}
		t.Setenv("TRAVERSAL_TUNNEL_COUNT", "9")
		if _, err := loadRawPipes(); err == nil {
			t.Fatal("accepted 9 tunnels")
		}
	})
	t.Run("pipe limits default to 4h and 15m idle", func(t *testing.T) {
		block, _ := publicKeyBlock(t, "prod-current")
		t.Setenv("TRAVERSAL_RAW_PIPES", "enabled")
		t.Setenv("TRAVERSAL_CAPABILITY_ISSUER", "traversal-raw-tunnel/prod")
		t.Setenv("TRAVERSAL_CAPABILITY_KEYS", block)
		cfg, err := loadRawPipes()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MaxLifetime != 4*time.Hour || cfg.IdleTimeout != 15*time.Minute {
			t.Fatalf("lifetime %s, idle %s", cfg.MaxLifetime, cfg.IdleTimeout)
		}
		t.Setenv("TRAVERSAL_RAW_PIPES_MAX_LIFETIME", "0")
		t.Setenv("TRAVERSAL_RAW_PIPES_IDLE_TIMEOUT", "30m")
		if cfg, err = loadRawPipes(); err != nil || cfg.MaxLifetime != 0 ||
			cfg.IdleTimeout != 30*time.Minute {
			t.Fatalf("overrides: %+v, %v", cfg, err)
		}
		t.Setenv("TRAVERSAL_RAW_PIPES_IDLE_TIMEOUT", "-1s")
		if _, err := loadRawPipes(); err == nil {
			t.Fatal("accepted a negative idle timeout")
		}
	})
	t.Run("rejects values that do not parse, rather than using defaults", func(t *testing.T) {
		block, _ := publicKeyBlock(t, "prod-current")
		t.Setenv("TRAVERSAL_RAW_PIPES", "enabled")
		t.Setenv("TRAVERSAL_CAPABILITY_ISSUER", "traversal-raw-tunnel/prod")
		t.Setenv("TRAVERSAL_CAPABILITY_KEYS", block)
		for key, value := range map[string]string{
			"TRAVERSAL_RAW_PIPES_MAX":            "fifty",
			"TRAVERSAL_RAW_PIPES_MAX_LIFETIME":   "4 hours",
			"TRAVERSAL_RAW_PIPES_IDLE_TIMEOUT":   "300", // no unit
			"TRAVERSAL_TUNNEL_COUNT":             "four",
			"TRAVERSAL_TUNNELS_PER_REPLICA":      "two",
			"TRAVERSAL_TUNNEL_STREAM_WINDOW":     "2MiB",
			"TRAVERSAL_TUNNEL_CONNECTION_WINDOW": "1e9",
		} {
			t.Run(key, func(t *testing.T) {
				t.Setenv(key, value)
				if _, err := loadRawPipes(); err == nil || !strings.Contains(err.Error(), key) {
					t.Fatalf("%s=%q: %v, want an error naming it", key, value, err)
				}
			})
		}
	})
	t.Run("caps the pipe count", func(t *testing.T) {
		block, _ := publicKeyBlock(t, "prod-current")
		t.Setenv("TRAVERSAL_RAW_PIPES", "enabled")
		t.Setenv("TRAVERSAL_CAPABILITY_ISSUER", "traversal-raw-tunnel/prod")
		t.Setenv("TRAVERSAL_CAPABILITY_KEYS", block)
		t.Setenv("TRAVERSAL_RAW_PIPES_MAX", strconv.Itoa(maxRawPipesMax))
		if _, err := loadRawPipes(); err != nil {
			t.Fatalf("the cap itself: %v", err)
		}
		t.Setenv("TRAVERSAL_RAW_PIPES_MAX", strconv.Itoa(maxRawPipesMax+1))
		if _, err := loadRawPipes(); err == nil {
			t.Fatal("accepted a pipe count over the cap")
		}
	})
	t.Run("dials directly unless an egress proxy is named", func(t *testing.T) {
		block, _ := publicKeyBlock(t, "prod-current")
		t.Setenv("TRAVERSAL_RAW_PIPES", "enabled")
		t.Setenv("TRAVERSAL_CAPABILITY_ISSUER", "traversal-raw-tunnel/prod")
		t.Setenv("TRAVERSAL_CAPABILITY_KEYS", block)
		// The connector's own proxy variables never route raw pipes.
		t.Setenv("HTTPS_PROXY", "http://corporate.proxy:3128")
		t.Setenv("EGRESS_PROXY_URL", "http://corporate.proxy:3128")
		cfg, err := loadRawPipes()
		if err != nil || cfg.EgressProxy != nil {
			t.Fatalf("got proxy %v, %v; want a direct dial", cfg.EgressProxy, err)
		}
		t.Setenv("TRAVERSAL_RAW_PIPES_EGRESS_PROXY", "")
		if cfg, err = loadRawPipes(); err != nil || cfg.EgressProxy != nil {
			t.Fatalf("empty value: got proxy %v, %v; want a direct dial", cfg.EgressProxy, err)
		}
		const proxy = "https://user:pw@pipes.proxy:8443" //nolint:gosec // G101: test fixture, intentional userinfo
		t.Setenv("TRAVERSAL_RAW_PIPES_EGRESS_PROXY", proxy)
		if cfg, err = loadRawPipes(); err != nil || cfg.EgressProxy == nil ||
			cfg.EgressProxy.String() != proxy {
			t.Fatalf("got proxy %v, %v", cfg.EgressProxy, err)
		}
		for _, bad := range []string{
			"pipes.proxy:3128", "socks5://pipes.proxy:1080", "http://", "http://pipes.proxy:3128/path",
			"http://pipes.proxy:99999", "http://pipes.proxy:3128?x=1", "://bad",
		} {
			t.Setenv("TRAVERSAL_RAW_PIPES_EGRESS_PROXY", bad)
			_, err := loadRawPipes()
			if err == nil || !strings.Contains(err.Error(), "TRAVERSAL_RAW_PIPES_EGRESS_PROXY") {
				t.Errorf("%q: %v, want an error naming the variable", bad, err)
			}
			if err != nil && strings.Contains(err.Error(), "pw") {
				t.Errorf("%q: error quotes credentials: %v", bad, err)
			}
		}
	})
}
