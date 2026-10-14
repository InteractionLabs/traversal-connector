package jws_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"

	"github.com/InteractionLabs/traversal-connector/connector-lib/jws"
)

// update regenerates testdata/vectors.json from vectorCases:
//
//	go test ./connector-lib/jws -run TestVectors -update
//
// ES256 signatures are randomized, so every token changes; the verdicts must
// not.
var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

const vectorsFile = "testdata/vectors.json"

// vectorFile is testdata/vectors.json. A port reads it as follows: for each
// vector, parse Token (at most MaxLen bytes, header typ Typ, x5c allowed
// only if Chained), check its signature against PublicKeyPEM, then decode
// its claims against Claims, ignoring unknown claims if Unknown is
// "ignore". The verdict is the first check that fails, in that order, or
// "ok".
type vectorFile struct {
	Comment      string       `json:"comment"`
	PublicKeyPEM string       `json:"public_key_pem"`
	Typ          string       `json:"typ"`
	MaxLen       int          `json:"max_len"`
	Claims       []claimField `json:"claims"`
	Vectors      []vector     `json:"vectors"`
}

// claimField is one claim the claims type names.
type claimField struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // "string" or "integer"
	Required bool   `json:"required"`
}

type vector struct {
	Name string `json:"name"`
	// Header and Payload are the JSON the token's first two segments
	// encode, for reading; the token is what is checked. Empty when the
	// token has no such segment or it is not UTF-8 JSON can carry.
	Header  string `json:"header,omitempty"`
	Payload string `json:"payload,omitempty"`
	Token   string `json:"token"`
	Chained bool   `json:"chained"`
	Unknown string `json:"unknown"` // "refuse" or "ignore"
	// Verdict is "ok", "malformed", "header", "signature" or "claims".
	Verdict string `json:"verdict"`
}

// vectorClaims is the claims type every vector decodes into.
type vectorClaims struct {
	Sub  string `json:"sub"`
	N    int64  `json:"n"`
	Note string `json:"note,omitempty"`
}

const (
	vectorTyp    = "example+jwt"
	vectorMaxLen = 1024
	goodHeader   = `{"alg":"ES256","typ":"example+jwt","kid":"k1"}`
	goodPayload  = `{"sub":"s","n":1}`
)

// vectorKey signs every vector; otherKey signs the wrong-key one. Derived
// from fixed seeds, so no key material is checked in.
var vectorKey, otherKey = seededKey("jws vectors"), seededKey("jws vectors: another key")

func seededKey(seed string) *ecdsa.PrivateKey {
	scalar := sha256.Sum256([]byte(seed))
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		panic(err)
	}
	return key
}

// vectorCase is one vector before it is signed. token, if set, builds the
// token from the signed one instead.
type vectorCase struct {
	name, header, payload string
	chained, ignore       bool
	key                   *ecdsa.PrivateKey
	token                 func(signed string) string
	verdict               string
}

var vectorCases = []vectorCase{
	{name: "ok", verdict: "ok"},
	{name: "ok, optional claim", payload: `{"sub":"s","n":1,"note":"x"}`, verdict: "ok"},
	{name: "ok, x5c where chained", chained: true, verdict: "ok",
		header: `{"alg":"ES256","typ":"example+jwt","kid":"k1","x5c":["AA=="]}`},
	{name: "ok, unknown claim ignored", ignore: true, verdict: "ok",
		payload: `{"sub":"s","n":1,"extra":{"a":[1,{"b":2}]}}`},

	{name: "malformed: two segments", verdict: "malformed",
		token: func(s string) string { return s[:strings.LastIndexByte(s, '.')] }},
	{name: "malformed: four segments", verdict: "malformed",
		token: func(s string) string { return s + ".x" }},
	{name: "malformed: over max_len", verdict: "malformed",
		payload: `{"sub":"` + strings.Repeat("s", vectorMaxLen) + `","n":1}`},

	{name: "header: alg none", verdict: "header",
		header: `{"alg":"none","typ":"example+jwt","kid":"k1"}`},
	{name: "header: alg ES384", verdict: "header",
		header: `{"alg":"ES384","typ":"example+jwt","kid":"k1"}`},
	{name: "header: alg case variant", verdict: "header",
		header: `{"alg":"es256","typ":"example+jwt","kid":"k1"}`},
	{name: "header: wrong typ", verdict: "header",
		header: `{"alg":"ES256","typ":"other+jwt","kid":"k1"}`},
	{name: "header: duplicate key", verdict: "header",
		header: `{"alg":"ES256","typ":"example+jwt","kid":"k1","kid":"k2"}`},
	{name: "header: case-variant key", verdict: "header",
		header: `{"alg":"ES256","typ":"example+jwt","kid":"k1","KID":"k2"}`},
	{name: "header: unknown field", verdict: "header",
		header: `{"alg":"ES256","typ":"example+jwt","kid":"k1","cty":"x"}`},
	{name: "header: missing kid", verdict: "header",
		header: `{"alg":"ES256","typ":"example+jwt"}`},
	{name: "header: x5c where not chained", verdict: "header",
		header: `{"alg":"ES256","typ":"example+jwt","kid":"k1","x5c":["AA=="]}`},
	{name: "header: trailing data", verdict: "header",
		header: `{"alg":"ES256","typ":"example+jwt","kid":"k1"}{}`},

	{name: "signature: another key", key: otherKey, verdict: "signature"},
	{name: "signature: payload changed after signing", verdict: "signature",
		token: func(s string) string {
			p := strings.Split(s, ".")
			p[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"t","n":1}`))
			return strings.Join(p, ".")
		}},
	{name: "signature: not base64url", verdict: "signature",
		token: func(s string) string { return s[:strings.LastIndexByte(s, '.')] + ".!!" }},
	{name: "signature: empty", verdict: "signature",
		token: func(s string) string { return s[:strings.LastIndexByte(s, '.')+1] }},

	{name: "claims: duplicate key", verdict: "claims", payload: `{"sub":"s","n":1,"n":2}`},
	{name: "claims: case-variant key", verdict: "claims", payload: `{"sub":"s","n":1,"N":2}`},
	{name: "claims: case-variant key, unknown claims ignored", ignore: true,
		verdict: "claims", payload: `{"sub":"s","n":1,"N":2}`},
	{name: "claims: case-variant key, nested in an ignored claim", ignore: true,
		verdict: "claims", payload: `{"sub":"s","n":1,"extra":{"a":1,"A":2}}`},
	{name: "claims: unknown claim refused", verdict: "claims",
		payload: `{"sub":"s","n":1,"extra":1}`},
	{name: "claims: missing required claim", verdict: "claims", payload: `{"sub":"s"}`},
	{name: "claims: null required claim", verdict: "claims", payload: `{"sub":null,"n":1}`},
	{name: "claims: mistyped claim", verdict: "claims", payload: `{"sub":"s","n":"1"}`},
	{name: "claims: trailing data", verdict: "claims", payload: `{"sub":"s","n":1} {}`},
	{name: "claims: invalid UTF-8", verdict: "claims", payload: "{\"sub\":\"\xff\",\"n\":1}"},
}

func (c vectorCase) build(t *testing.T) vector {
	t.Helper()
	h, p, key := c.header, c.payload, c.key
	if h == "" {
		h = goodHeader
	}
	if p == "" {
		p = goodPayload
	}
	if key == nil {
		key = vectorKey
	}
	input := base64.RawURLEncoding.EncodeToString([]byte(h)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(p))
	sig, err := jwt.SigningMethodES256.Sign(input, key)
	if err != nil {
		t.Fatal(err)
	}
	v := vector{Name: c.name, Chained: c.chained, Unknown: "refuse",
		Token: input + "." + base64.RawURLEncoding.EncodeToString(sig), Verdict: c.verdict}
	if c.ignore {
		v.Unknown = "ignore"
	}
	if c.token != nil {
		v.Token = c.token(v.Token)
	}
	v.Header, v.Payload = segments(v.Token)
	return v
}

// segments are token's header and payload as text, if it has three segments
// that decode to UTF-8.
func segments(token string) (header, payload string) {
	p := strings.Split(token, ".")
	if len(p) != 3 {
		return "", ""
	}
	h, herr := base64.RawURLEncoding.DecodeString(p[0])
	b, berr := base64.RawURLEncoding.DecodeString(p[1])
	if herr != nil || berr != nil || !utf8.Valid(h) || !utf8.Valid(b) {
		return "", ""
	}
	return string(h), string(b)
}

func writeVectors(t *testing.T) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&vectorKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	f := vectorFile{
		Comment: "Golden compact ES256 JWS vectors for connector-lib/jws and its ports. " +
			"Generated by connector-lib/jws/vectors_test.go (-update); see vectorFile there.",
		PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		Typ:          vectorTyp,
		MaxLen:       vectorMaxLen,
		Claims: []claimField{
			{"sub", "string", true}, {"n", "integer", true}, {"note", "string", false},
		},
	}
	for _, c := range vectorCases {
		f.Vectors = append(f.Vectors, c.build(t))
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorsFile, append(b, '\n'), 0o644); err != nil { //nolint:gosec // testdata
		t.Fatal(err)
	}
}

// TestVectors runs every golden vector through Parse and Verify and checks
// its verdict, so this package and its ports agree on each.
func TestVectors(t *testing.T) {
	if *update {
		writeVectors(t)
	}
	raw, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	var f vectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(f.PublicKeyPEM))
	if block == nil {
		t.Fatal("public_key_pem is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok {
		t.Fatalf("public key: %v", err)
	}
	if len(f.Vectors) != len(vectorCases) {
		t.Fatalf("%s has %d vectors, the cases %d: run with -update", vectorsFile,
			len(f.Vectors), len(vectorCases))
	}
	for i, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v.Name != vectorCases[i].name || v.Verdict != vectorCases[i].verdict {
				t.Fatalf("%s is stale: run with -update", vectorsFile)
			}
			if h, p := segments(v.Token); h != v.Header || p != v.Payload {
				t.Fatal("header or payload does not match the token")
			}
			if got := verdict(v, f, key); got != v.Verdict {
				t.Fatalf("verdict %q, want %q", got, v.Verdict)
			}
		})
	}
}

func verdict(v vector, f vectorFile, key *ecdsa.PublicKey) string {
	tok, err := jws.Parse(v.Token, f.MaxLen, f.Typ, v.Chained)
	if err == nil {
		var c vectorClaims
		err = tok.Verify(key, &c, jws.Unknown(v.Unknown == "ignore"))
	}
	for name, e := range map[string]error{"ok": nil, "malformed": jws.ErrMalformed,
		"header": jws.ErrHeader, "signature": jws.ErrSignature, "claims": jws.ErrClaims} {
		if errors.Is(err, e) || err == nil && e == nil {
			return name
		}
	}
	return "unexpected: " + err.Error()
}
