package signedconfig

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	for name, object := range map[string]string{
		"unsigned":            doc,
		"for a sibling":       string(signed),
		"another key":         string(byOther),
		"unknown kid":         string(unknownKid),
		"document changed":    tampered,
		"signature line only": strings.SplitN(string(signed), "\n", 2)[0],
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

// TestVerifyDecodesStrictly: a validly signed config whose claims repeat a
// key, exactly or by case, is refused, as capabilities are.
func TestVerifyDecodesStrictly(t *testing.T) {
	key := capabilitytest.Key("config")
	keys := map[string]*ecdsa.PublicKey{"k": &key.PublicKey}
	sum := sha256.Sum256([]byte(doc))
	digest := hex.EncodeToString(sum[:])
	header := b64([]byte(`{"alg":"ES256","typ":"` + tokenType + `","kid":"k"}`))
	base := `"aud":"` + Audience + `","connector_id":"` + connector + `","version":7,"sha256":"` + digest + `"`
	for name, claims := range map[string]string{
		"duplicate key":    `{` + base + `,"version":8}`,
		"case-variant key": `{` + base + `,"Version":8}`,
		"trailing data":    `{` + base + `} {}`,
		"well formed (ok)": `{` + base + `}`,
	} {
		input := header + "." + b64([]byte(claims))
		sig, err := jwt.SigningMethodES256.Sign(input, key)
		if err != nil {
			t.Fatal(err)
		}
		object := Prefix + input + "." + b64(sig) + "\n" + doc
		_, _, err = Verify([]byte(object), connector, keys)
		if ok := strings.HasSuffix(name, "(ok)"); ok != (err == nil) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// TestStrictHeader: the header holds exactly alg, typ and kid; x5c, a
// repeated key, a case variant or a capability's typ is refused.
func TestStrictHeader(t *testing.T) {
	key := capabilitytest.Key("config")
	keys := map[string]*ecdsa.PublicKey{"k": &key.PublicKey}
	signed, err := Sign(key, "k", connector, 7, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.Split(strings.TrimPrefix(strings.SplitN(string(signed), "\n", 2)[0],
		Prefix), ".")[1]
	typ := `"typ":"` + tokenType + `"`
	for name, h := range map[string]string{
		"x5c":              `{"alg":"ES256",` + typ + `,"kid":"k","x5c":["AA=="]}`,
		"duplicate kid":    `{"alg":"ES256",` + typ + `,"kid":"x","kid":"k"}`,
		"case-variant kid": `{"alg":"ES256",` + typ + `,"kid":"k","Kid":"x"}`,
		"capability typ":   `{"alg":"ES256","typ":"traversal-capability+jwt","kid":"k"}`,
		"exact (ok)":       `{"alg":"ES256",` + typ + `,"kid":"k"}`,
	} {
		input := b64([]byte(h)) + "." + payload
		sig, err := jwt.SigningMethodES256.Sign(input, key)
		if err != nil {
			t.Fatal(err)
		}
		object := Prefix + input + "." + b64(sig) + "\n" + doc
		_, _, err = Verify([]byte(object), connector, keys)
		if ok := strings.HasSuffix(name, "(ok)"); ok != (err == nil) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
