package capability_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

var update = flag.Bool("update", false, "regenerate testdata/vectors.json")

const vectorsPath = "testdata/vectors.json"

// vectorFile is the interoperability contract for capability signers and
// validators in other languages. A signer must canonicalize every host as
// listed, and a validator must reach each token's result at time now.
type vectorFile struct {
	Description     string        `json:"description"`
	Issuer          string        `json:"issuer"`
	AllowedSubjects []string      `json:"allowed_subjects"`
	Now             int64         `json:"now"`
	Keys            []vectorKey   `json:"keys"`
	Hosts           []hostVector  `json:"hosts"`
	Tokens          []tokenVector `json:"tokens"`
}

type vectorKey struct {
	KID string `json:"kid"`
	// Seed derives the private key: its scalar is SHA-256(seed).
	Seed         string `json:"seed"`
	PublicKeyPEM string `json:"public_key_pem"`
}

type hostVector struct {
	Input     string `json:"input"`
	Canonical string `json:"canonical,omitempty"`
	Valid     bool   `json:"valid"`
}

type tokenVector struct {
	Name     string         `json:"name"`
	Token    string         `json:"token"`
	Expected expectedVector `json:"expected"`
	// Result is "ok" or the capability.Code the validator must report.
	Result string `json:"result"`
}

type expectedVector struct {
	ConnectorID    string `json:"connector_id"`
	OrganizationID string `json:"organization_id"`
	Host           string `json:"host"`
	Port           uint16 `json:"port"`
	Mode           string `json:"mode"`
}

const (
	currentSeed = "traversal-connector capability test key: current"
	nextSeed    = "traversal-connector capability test key: next"
)

type tokenCase struct {
	name string
	// sign returns the token for base claims.
	sign   func(t testing.TB, c capability.Claims) string
	result capability.Code
}

func mutated(mutate func(*capability.Claims)) func(testing.TB, capability.Claims) string {
	return func(t testing.TB, c capability.Claims) string {
		mutate(&c)
		return sign(t, c)
	}
}

// rawPayload signs base claims re-encoded by edit, for payloads a correct
// signer would never produce.
func rawPayload(edit func(string) string) func(testing.TB, capability.Claims) string {
	return func(t testing.TB, c capability.Claims) string {
		payload, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		return signRaw(t, `{"alg":"ES256","kid":"`+currentKID+`","typ":"`+
			capability.TokenType+`"}`, edit(string(payload)))
	}
}

func rawHeader(header string) func(testing.TB, capability.Claims) string {
	return func(t testing.TB, c capability.Claims) string {
		payload, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		return signRaw(t, header, string(payload))
	}
}

func signRaw(t testing.TB, header, payload string) string {
	t.Helper()
	token, err := capabilitytest.SignRaw(currentKey, []byte(header), []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

var tokenCases = []tokenCase{
	{"valid", mutated(func(*capability.Claims) {}), ""},
	{"valid with next key", func(t testing.TB, c capability.Claims) string {
		token, err := capabilitytest.Sign(nextKey, nextKID, c)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}, ""},
	{"unknown kid", func(t testing.TB, c capability.Claims) string {
		token, err := capabilitytest.Sign(currentKey, "retired-key", c)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}, capability.CodeUnknownKey},
	{"signed by another trusted key", func(t testing.TB, c capability.Claims) string {
		token, err := capabilitytest.Sign(nextKey, currentKID, c)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}, capability.CodeInvalidSignature},
	{"wrong issuer", mutated(func(c *capability.Claims) {
		c.Issuer = "traversal-raw-tunnel/prod"
	}), capability.CodeWrongIssuer},
	{"wrong audience", mutated(func(c *capability.Claims) { c.Audience = "traversal" }),
		capability.CodeWrongAudience},
	{"expired", mutated(func(c *capability.Claims) {
		c.IssuedAt, c.ExpiresAt = c.IssuedAt-200, c.IssuedAt-80
	}), capability.CodeExpired},
	{"not yet valid", mutated(func(c *capability.Claims) {
		c.IssuedAt, c.ExpiresAt = c.IssuedAt+100, c.ExpiresAt+100
	}), capability.CodeNotYetValid},
	{"lifetime too long", mutated(func(c *capability.Claims) { c.ExpiresAt = c.IssuedAt + 301 }),
		capability.CodeLifetimeTooLong},
	{"forbidden subject", mutated(func(c *capability.Claims) { c.Subject = "integration-proxy" }),
		capability.CodeForbiddenSubject},
	{"wrong organization", mutated(func(c *capability.Claims) { c.OrganizationID = "org-2" }),
		capability.CodeWrongTenant},
	{"wrong connector", mutated(func(c *capability.Claims) { c.ConnectorID = "connector-2" }),
		capability.CodeWrongConnector},
	{"wrong host", mutated(func(c *capability.Claims) { c.Host = "cache.internal" }),
		capability.CodeWrongDestination},
	{"wrong port", mutated(func(c *capability.Claims) { c.Port = 5433 }),
		capability.CodeWrongDestination},
	{"non-canonical host", mutated(func(c *capability.Claims) { c.Host = "DB.internal" }),
		capability.CodeMalformed},
	{"unknown mode", mutated(func(c *capability.Claims) { c.Mode = "tls-terminate" }),
		capability.CodeUnsupportedMode},
	{"empty session id", mutated(func(c *capability.Claims) { c.SessionID = "" }),
		capability.CodeMalformed},
	{"extra claim", rawPayload(func(p string) string {
		return strings.Replace(p, "{", `{"scope":"all",`, 1)
	}), capability.CodeMalformed},
	{"missing claim", rawPayload(func(p string) string {
		return strings.Replace(p, `"traffic_class":"standard",`, "", 1)
	}), capability.CodeMalformed},
	{"duplicate claim", rawPayload(func(p string) string {
		return strings.Replace(p, "{", `{"connector_id":"connector-2",`, 1)
	}), capability.CodeMalformed},
	{"claim in another case", rawPayload(func(p string) string {
		return strings.Replace(p, `"connector_id"`, `"Connector_ID"`, 1)
	}), capability.CodeMalformed},
	{"port as string", rawPayload(func(p string) string {
		return strings.Replace(p, `"port":5432`, `"port":"5432"`, 1)
	}), capability.CodeMalformed},
	{"audience as array", rawPayload(func(p string) string {
		return strings.Replace(
			p,
			`"aud":"traversal-raw-tunnel"`,
			`"aud":["traversal-raw-tunnel"]`,
			1,
		)
	}), capability.CodeMalformed},
	{"trailing data", rawPayload(func(p string) string { return p + "{}" }),
		capability.CodeMalformed},
	{"alg none", rawHeader(`{"alg":"none","kid":"` + currentKID + `","typ":"` +
		capability.TokenType + `"}`), capability.CodeMalformed},
	{"wrong typ", rawHeader(`{"alg":"ES256","kid":"` + currentKID + `","typ":"JWT"}`),
		capability.CodeMalformed},
	{"extra header field", rawHeader(`{"alg":"ES256","kid":"` + currentKID + `","typ":"` +
		capability.TokenType + `","jku":"https://example.com"}`), capability.CodeMalformed},
}

var hostVectors = func() []hostVector {
	out := make([]hostVector, 0, len(hostCases))
	for _, tc := range hostCases {
		// JSON strings cannot carry invalid UTF-8.
		if !utf8.ValidString(tc.input) {
			continue
		}
		out = append(out, hostVector{
			Input: tc.input, Canonical: tc.canonical, Valid: tc.canonical != "",
		})
	}
	return out
}()

func vectorExpected() expectedVector {
	e := expected()
	return expectedVector{
		ConnectorID:    e.ConnectorID,
		OrganizationID: e.OrganizationID,
		Host:           e.Host,
		Port:           e.Port,
		Mode:           capability.ModePassthrough,
	}
}

func generateVectors(t *testing.T) vectorFile {
	t.Helper()
	f := vectorFile{
		Description: "Connector capability interoperability vectors. Keys are derived from " +
			"their seeds and are for tests only. Regenerate with: go test " +
			"./connector-lib/capability -run TestVectors -update",
		Issuer:          testIssuer,
		AllowedSubjects: []string{testSubject},
		Now:             testNow.Unix(),
		Keys: []vectorKey{
			{KID: currentKID, Seed: currentSeed, PublicKeyPEM: publicKeyPEM(t, currentKey)},
			{KID: nextKID, Seed: nextSeed, PublicKeyPEM: publicKeyPEM(t, nextKey)},
		},
		Hosts: hostVectors,
	}
	for _, tc := range tokenCases {
		result := string(tc.result)
		if result == "" {
			result = "ok"
		}
		f.Tokens = append(f.Tokens, tokenVector{
			Name:     tc.name,
			Token:    tc.sign(t, validClaims(testNow)),
			Expected: vectorExpected(),
			Result:   result,
		})
	}
	return f
}

func publicKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// TestVectors verifies the committed vectors, and that they still match the
// cases above apart from the randomized signatures.
func TestVectors(t *testing.T) {
	if *update {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(generateVectors(t)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsPath, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var file vectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}

	want := generateVectors(t)
	stripTokens := func(f vectorFile) vectorFile {
		f.Tokens = slices.Clone(f.Tokens)
		for i := range f.Tokens {
			f.Tokens[i].Token = ""
		}
		return f
	}
	gotJSON, _ := json.Marshal(stripTokens(file))
	wantJSON, _ := json.Marshal(stripTokens(want))
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatal("testdata/vectors.json is stale; rerun with -update")
	}

	keys := map[string]*ecdsa.PublicKey{}
	for _, k := range file.Keys {
		key, err := capability.ParsePublicKeyPEM([]byte(k.PublicKeyPEM))
		if err != nil {
			t.Fatal(err)
		}
		if !key.Equal(&capabilitytest.Key(k.Seed).PublicKey) {
			t.Fatalf("key %s does not match its seed", k.KID)
		}
		keys[k.KID] = key
	}
	for _, h := range file.Hosts {
		got, err := capability.CanonicalHost(h.Input)
		if (err == nil) != h.Valid || got != h.Canonical {
			t.Errorf("host %q: got %q, %v", h.Input, got, err)
		}
	}
	for _, tv := range file.Tokens {
		v, err := capability.NewVerifier(capability.VerifierConfig{
			Issuer:          file.Issuer,
			Keys:            keys,
			AllowedSubjects: file.AllowedSubjects,
			Now:             func() time.Time { return time.Unix(file.Now, 0) },
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = v.Verify(tv.Token, capability.Expected{
			ConnectorID:    tv.Expected.ConnectorID,
			OrganizationID: tv.Expected.OrganizationID,
			Host:           tv.Expected.Host,
			Port:           tv.Expected.Port,
			Mode:           pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH,
		})
		got := string(codeOf(err))
		if err == nil {
			got = "ok"
		}
		if got != tv.Result {
			t.Errorf("token %q: got %s (%v), want %s", tv.Name, got, err, tv.Result)
		}
	}
}
