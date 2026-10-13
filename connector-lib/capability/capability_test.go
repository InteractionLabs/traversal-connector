package capability_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strconv"
	"strings"
	"testing"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
)

const (
	issuer    = capability.IssuerPrefix + "test"
	connector = "c1"
)

var key = capabilitytest.Key("capability test")

func verifier(t *testing.T) *capability.Verifier {
	t.Helper()
	v, err := capability.NewVerifier(pinnedConfig())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func pinnedConfig() capability.VerifierConfig {
	return capability.VerifierConfig{Issuer: issuer, Subject: "integration-proxy",
		Keys: map[string]*ecdsa.PublicKey{"k1": &key.PublicKey}}
}

func sign(t *testing.T, mutate func(*capability.Claims)) string {
	t.Helper()
	c := capabilitytest.Claims(issuer, connector, "db.internal", 5432)
	if mutate != nil {
		mutate(&c)
	}
	token, err := capability.Sign(key, "k1", c)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestVerify(t *testing.T) {
	v := verifier(t)
	if _, err := v.Verify(sign(t, nil), connector, "db.internal", 5432); err != nil {
		t.Fatal(err)
	}
	other := capabilitytest.Key("another key")
	foreign, _ := capability.Sign(
		other,
		"k1",
		capabilitytest.Claims(issuer, connector, "db.internal", 5432),
	)
	for name, c := range map[string]struct {
		token, connector, host string
		want                   rawpipe.Reason
	}{
		"wrong connector":   {sign(t, nil), "c2", "db.internal", rawpipe.WrongConnector},
		"wrong destination": {sign(t, nil), connector, "other.internal", rawpipe.WrongDestination},
		"foreign key":       {foreign, connector, "db.internal", rawpipe.InvalidCapability},
		"garbage":           {"a.b.c", connector, "db.internal", rawpipe.InvalidCapability},
		"wrong subject": {sign(t, func(c *capability.Claims) { c.Subject = "someone" }),
			connector, "db.internal", rawpipe.InvalidCapability},
		"expired": {sign(t, func(c *capability.Claims) { c.IssuedAt -= 600; c.ExpiresAt -= 600 }),
			connector, "db.internal", rawpipe.InvalidCapability},
		"tampered": {strings.Replace(sign(t, nil), ".", ".e30", 1), connector, "db.internal",
			rawpipe.InvalidCapability},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(c.token, c.connector, c.host, 5432)
			if rawpipe.ReasonOf(err, "") != c.want {
				t.Fatalf("got %v, want %s", err, c.want)
			}
		})
	}
	t.Run("open limit", func(t *testing.T) {
		token := sign(t, func(c *capability.Claims) { c.JTI = "once" })
		for range 4 {
			if _, err := v.Verify(token, connector, "db.internal", 5432); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := v.Verify(token, connector, "db.internal", 5432); rawpipe.ReasonOf(err, "") !=
			rawpipe.Exhausted {
			t.Fatalf("fifth open: %v", err)
		}
	})
}

func TestSignRefusesBadClaims(t *testing.T) {
	c := capabilitytest.Claims(issuer, connector, "DB.internal", 5432)
	if _, err := capability.Sign(key, "k1", c); err == nil {
		t.Fatal("signed a non-canonical host")
	}
	c = capabilitytest.Claims(issuer, connector, "db.internal", 5432)
	c.ExpiresAt = c.IssuedAt + 3600
	if _, err := capability.Sign(key, "k1", c); err == nil {
		t.Fatal("signed an hour-long capability")
	}
}

func TestCanonical(t *testing.T) {
	for in, want := range map[string]string{
		"DB.Internal.": "db.internal", "::ffff:10.0.0.1": "10.0.0.1", "svc_a.ns": "svc_a.ns",
		"127.1": "", "0x7f.1": "", "a..b": "", "fe80::1%eth0": "", "bad host": "", "": "",
		// Hex-looking last labels are names (ccTLDs, AD estates); only the
		// forms a URL parser reads as IPv4 are refused.
		"db": "db", "db.example.de": "db.example.de", "db.example.ca": "db.example.ca",
		"api.example.be": "api.example.be", "pg.cafe": "pg.cafe", "svc.ad": "svc.ad",
		"postgres.db": "postgres.db", "a.0x": "", "a.0xff": "", "a.123": "", "x.0a": "x.0a",
	} {
		got, ok := capability.Canonical(in)
		if ok != (want != "") || got != want && ok {
			t.Errorf("Canonical(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for authority, ok := range map[string]bool{
		"db.internal:5432": true, "[::1]:22": true, "db.internal:05432": false,
		"[db.internal]:1": false, "DB.internal:1": false, "db.internal:0": false,
	} {
		if _, _, got := capability.SplitAuthority(authority); got != ok {
			t.Errorf("SplitAuthority(%q) = %v", authority, got)
		}
	}
}

func TestParseKeys(t *testing.T) {
	block := func(kid string) string {
		der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		return string(
			pem.EncodeToMemory(
				&pem.Block{
					Type:    "PUBLIC KEY",
					Headers: map[string]string{"Key-ID": kid},
					Bytes:   der,
				},
			),
		)
	}
	if keys, err := capability.ParseKeys([]byte(block("a") + block("b"))); err != nil ||
		len(keys) != 2 {
		t.Fatalf("two keys: %v %v", keys, err)
	}
	for name, bundle := range map[string]string{"empty": "", "no kid": block(""), "duplicate": block("a") + block("a")} {
		if _, err := capability.ParseKeys([]byte(bundle)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// BenchmarkVerifyManyLive: verify cost must not grow with live jtis (one per
// recent capability), since every tenant's opens share one verifier.
func BenchmarkVerifyManyLive(b *testing.B) {
	for _, live := range []int{0, 60000} {
		b.Run(strconv.Itoa(live), func(b *testing.B) {
			v, _ := capability.NewVerifier(pinnedConfig())
			mint := func(i int) string {
				c := capabilitytest.Claims(issuer, connector, "db.internal", 5432)
				c.JTI = "jti-" + strconv.Itoa(i)
				tok, _ := capability.Sign(key, "k1", c)
				return tok
			}
			for i := range live {
				_, _ = v.Verify(mint(i), connector, "db.internal", 5432)
			}
			toks := make([]string, b.N)
			for i := range toks {
				toks[i] = mint(live + i)
			}
			b.ResetTimer()
			for i := range b.N {
				_, _ = v.Verify(toks[i], connector, "db.internal", 5432)
			}
		})
	}
}

// TestStrictClaims: duplicate or case-variant keys and unknown fields are
// refused even when correctly signed.
func TestStrictClaims(t *testing.T) {
	good := sign(t, nil)
	parts := strings.Split(good, ".")
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	for name, body := range map[string]string{
		"duplicate":   strings.Replace(string(claims), "{", `{"host":"evil.test",`, 1),
		"case":        strings.Replace(string(claims), "{", `{"HOST":"evil.test",`, 1),
		"unknown key": strings.Replace(string(claims), "{", `{"extra":1,`, 1),
	} {
		payload := base64.RawURLEncoding.EncodeToString([]byte(body))
		tok := resign(t, parts[0], payload)
		if _, err := verifier(t).Verify(tok, connector, "db.internal", 5432); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := verifier(t).Verify(good, connector, "db.internal", 5432); err != nil {
		t.Errorf("good token: %v", err)
	}
}

// resign signs header.payload with the test key, as the issuer would.
func resign(t *testing.T, header, payload string) string {
	t.Helper()
	return resignWith(t, key, header, payload)
}

// resignWith signs header.payload with k.
func resignWith(t *testing.T, k *ecdsa.PrivateKey, header, payload string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(header + "." + payload))
	r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig)
}
