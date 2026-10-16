package capability_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

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
	return capability.VerifierConfig{Issuer: issuer, Subject: capability.SubjectIntegrationProxy,
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
		"wrong subject": {sign(t, func(c *capability.Claims) { c.Subject = "someone" }),
			connector, "db.internal", rawpipe.InvalidCapability},
		"expired": {sign(t, func(c *capability.Claims) { c.IssuedAt -= 600; c.ExpiresAt -= 600 }),
			connector, "db.internal", rawpipe.InvalidCapability},
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

// TestClaimsDecoding: an unknown claim, of any JSON type, is ignored; a
// duplicate or case-variant key (at any depth), trailing data, invalid UTF-8,
// and a missing, null or mistyped required claim are refused even when
// correctly signed.
func TestClaimsDecoding(t *testing.T) {
	good := sign(t, nil)
	parts := strings.Split(good, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	claims := string(raw)
	with := func(prefix string) string { return strings.Replace(claims, "{", "{"+prefix, 1) }
	without := func(key string) string {
		var m map[string]json.RawMessage
		_ = json.Unmarshal(raw, &m)
		delete(m, key)
		b, _ := json.Marshal(m)
		return string(b)
	}
	for name, c := range map[string]struct {
		body string
		ok   bool
	}{
		"unknown string":        {with(`"note":"informational",`), true},
		"unknown object":        {with(`"extra":{"a":[1,{"b":2}]},`), true},
		"unknown number":        {with(`"n":1.5,`), true},
		"unknown, once a claim": {with(`"mode":"inspect",`), true},
		"duplicate":             {with(`"host":"evil.test",`), false},
		"case variant":          {with(`"HOST":"evil.test",`), false},
		"nested duplicate":      {with(`"extra":{"a":1,"A":2},`), false},
		"trailing data":         {claims + `{}`, false},
		"invalid UTF-8":         {with("\"note\":\"\xff\","), false},
		"missing claim":         {without("connector_id"), false},
		"null claim":            {strings.Replace(without("jti"), "{", `{"jti":null,`, 1), false},
		"mistyped port":         {strings.Replace(without("port"), "{", `{"port":"5432",`, 1), false},
		"mistyped iat":          {strings.Replace(without("iat"), "{", `{"iat":"1",`, 1), false},
	} {
		tok := resign(t, parts[0], base64.RawURLEncoding.EncodeToString([]byte(c.body)))
		_, err := verifier(t).Verify(tok, connector, "db.internal", 5432)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v, want accepted %v", name, err, c.ok)
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
	sig, err := jwt.SigningMethodES256.Sign(header+"."+payload, k)
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig)
}
