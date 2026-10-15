package signedconfig

import (
	"crypto/ecdsa"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pelletier/go-toml/v2"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
)

const (
	connector = "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d00"
	sibling   = "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d01"
	doc       = "schema_version = 1\n[redaction]\nrules = []\n"
)

func TestSignVerify(t *testing.T) {
	key := capabilitytest.Key("config")
	other := capabilitytest.Key("other")
	keys := map[string]*ecdsa.PublicKey{"k": &key.PublicKey}
	signed, err := Sign(key, "k", connector, 7, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	got, c, err := Verify(signed, connector, keys)
	if err != nil || string(got) != doc || c.Version != 7 {
		t.Fatalf("verify: %v %q %+v", err, got, c)
	}
	// Connectors without config keys parse the signed object as before.
	var v map[string]any
	if err := toml.Unmarshal(signed, &v); err != nil || v["schema_version"] != int64(1) {
		t.Fatalf("old parser: %v %v", err, v)
	}

	byOther, _ := Sign(other, "k", connector, 7, []byte(doc))
	unknownKid, _ := Sign(key, "k2", connector, 7, []byte(doc))
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
		if _, _, err := Verify([]byte(object), want, keys); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
