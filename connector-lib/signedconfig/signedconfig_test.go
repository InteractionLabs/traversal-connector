package signedconfig

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pelletier/go-toml/v2"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
)

const (
	connector = "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d00"
	sibling   = "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d01"
	doc       = "schema_version = 1\n[redaction]\nrules = []\n"
)

// now, issued and expires are the times the tests sign and verify at.
var (
	now     = time.Unix(1_800_000_000, 0)
	issued  = now.Add(-time.Hour)
	expires = now.Add(24 * time.Hour)
)

func TestSignVerify(t *testing.T) {
	key := capabilitytest.Key("config")
	other := capabilitytest.Key("other")
	keys := map[string]*ecdsa.PublicKey{"k": &key.PublicKey}
	signed, err := Sign(key, "k", connector, 7, issued, expires, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	got, c, err := Verify(signed, connector, keys, now)
	if err != nil || string(got) != doc || c.Version != 7 || c.IssuedAt != issued.Unix() ||
		c.ExpiresAt != expires.Unix() {
		t.Fatalf("verify: %v %q %+v", err, got, c)
	}
	// Connectors without config keys parse the signed object as before.
	var v map[string]any
	if err := toml.Unmarshal(signed, &v); err != nil || v["schema_version"] != int64(1) {
		t.Fatalf("old parser: %v %v", err, v)
	}

	byOther, _ := Sign(other, "k", connector, 7, issued, expires, []byte(doc))
	unknownKid, _ := Sign(key, "k2", connector, 7, issued, expires, []byte(doc))
	tampered := strings.Replace(string(signed), "rules = []", "rules = [] ", 1)
	payload := strings.Split(strings.TrimPrefix(strings.SplitN(string(signed), "\n", 2)[0],
		Prefix), ".")[1]
	capHeader := b64([]byte(`{"alg":"ES256","typ":"traversal-capability+jwt","kid":"k"}`))
	capSig, err := jwt.SigningMethodES256.Sign(capHeader+"."+payload, key)
	if err != nil {
		t.Fatal(err)
	}
	for name, object := range map[string]string{
		"unsigned":            doc,
		"for a sibling":       string(signed),
		"another key":         string(byOther),
		"unknown kid":         string(unknownKid),
		"document changed":    tampered,
		"signature line only": strings.SplitN(string(signed), "\n", 2)[0],
		"capability typ":      Prefix + capHeader + "." + payload + "." + b64(capSig) + "\n" + doc,
	} {
		want := connector
		if name == "for a sibling" {
			want = sibling
		}
		if _, _, err := Verify([]byte(object), want, keys, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestValidityWindow: a config verifies from MaxClockSkew before its iat to
// MaxClockSkew after its exp, and not outside that. One missing iat or exp,
// or whose window is not one, never verifies, and is never signed.
func TestValidityWindow(t *testing.T) {
	key := capabilitytest.Key("config")
	keys := map[string]*ecdsa.PublicKey{"k": &key.PublicKey}
	signed, err := Sign(key, "k", connector, 7, issued, expires, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		at    time.Time
		valid bool
	}{
		{issued, true},
		{expires.Add(-time.Second), true},
		{issued.Add(-time.Minute), true}, // a clock a minute behind the signer's
		{expires.Add(time.Minute), true}, // or ahead
		{issued.Add(-MaxClockSkew + time.Second), true},
		{expires.Add(MaxClockSkew - time.Second), true},
		{issued.Add(-MaxClockSkew - time.Second), false}, // issued too far ahead
		{expires.Add(MaxClockSkew), false},               // expired
		{expires.Add(30 * 24 * time.Hour), false},
	} {
		if _, _, err := Verify(signed, connector, keys, c.at); (err == nil) != c.valid {
			t.Errorf("at iat%+v: %v, want valid %v", c.at.Sub(issued), err, c.valid)
		}
	}
	for _, w := range [][2]time.Time{{issued, issued}, {issued, issued.Add(-time.Second)},
		{time.Unix(0, 0), expires}} {
		if _, err := Sign(key, "k", connector, 7, w[0], w[1], []byte(doc)); err == nil {
			t.Errorf("signed iat %v, exp %v", w[0], w[1])
		}
	}
	// Signed outside Sign: each window holds now but is not a window.
	sum := sha256.Sum256([]byte(doc))
	for name, window := range map[string]string{
		"no iat":         fmt.Sprintf(`"exp":%d`, expires.Unix()),
		"no exp":         fmt.Sprintf(`"iat":%d`, issued.Unix()),
		"exp before iat": fmt.Sprintf(`"iat":%d,"exp":%d`, now.Unix()+60, now.Unix()+30),
		"iat of 0":       fmt.Sprintf(`"iat":0,"exp":%d`, expires.Unix()),
	} {
		payload := fmt.Sprintf(`{"aud":%q,"connector_id":%q,"version":7,"sha256":%q,%s}`,
			Audience, connector, hex.EncodeToString(sum[:]), window)
		input := b64([]byte(`{"alg":"ES256","typ":"traversal-config+jwt","kid":"k"}`)) + "." +
			b64([]byte(payload))
		sig, err := jwt.SigningMethodES256.Sign(input, key)
		if err != nil {
			t.Fatal(err)
		}
		object := Prefix + input + "." + b64(sig) + "\n" + doc
		if _, _, err := Verify([]byte(object), connector, keys, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
