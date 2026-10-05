package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
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
	if !keys["prod-current"].Equal(currentKey) || !keys["prod-next"].Equal(nextKey) || len(keys) != 2 {
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
}
