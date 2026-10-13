package capability_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
)

const (
	chainHost   = "edge.staging.traversal.com"
	chainIssuer = capability.IssuerPrefix + "staging"
)

var (
	rootKey     = capabilitytest.Key("capability test: root")
	nextRootKey = capabilitytest.Key("capability test: next root")
	envKey      = capabilitytest.Key("capability test: environment")
)

func testRoot(t *testing.T, k *ecdsa.PrivateKey) *capabilitytest.Root {
	t.Helper()
	root, err := capabilitytest.NewRoot(k, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// envCert is a valid environment certificate for envKey, after mutate.
func envCert(
	t *testing.T,
	root *capabilitytest.Root,
	mutate func(*capabilitytest.EnvironmentCert),
) []byte {
	t.Helper()
	spec := capabilitytest.EnvironmentCert{
		Key:       &envKey.PublicKey,
		Issuer:    capability.IssuerURIPrefix + "staging",
		Hosts:     []string{chainHost},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	if mutate != nil {
		mutate(&spec)
	}
	der, err := root.Issue(spec)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func rootsConfig(roots ...*capabilitytest.Root) capability.VerifierConfig {
	cfg := capability.VerifierConfig{Subject: "integration-proxy", ControllerHost: chainHost}
	for _, r := range roots {
		cfg.Roots = append(cfg.Roots, r.Certificate)
	}
	return cfg
}

func newVerifier(t *testing.T, cfg capability.VerifierConfig) *capability.Verifier {
	t.Helper()
	v, err := capability.NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func chainedClaims(mutate func(*capability.Claims)) capability.Claims {
	c := capabilitytest.Claims(chainIssuer, connector, "db.internal", 5432)
	if mutate != nil {
		mutate(&c)
	}
	return c
}

func signChained(
	t *testing.T,
	k *ecdsa.PrivateKey,
	kid string,
	c capability.Claims,
	x5c ...[]byte,
) string {
	t.Helper()
	token, err := capability.SignChained(k, kid, x5c, c)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// rawChained signs a token whose header is exactly h, for headers SignChained
// refuses to produce.
func rawChained(t *testing.T, h string) string {
	t.Helper()
	p, _ := json.Marshal(chainedClaims(nil))
	return resignWith(t, envKey, base64.RawURLEncoding.EncodeToString([]byte(h)),
		base64.RawURLEncoding.EncodeToString(p))
}

func verifyChained(v *capability.Verifier, token string) error {
	_, err := v.Verify(token, connector, "db.internal", 5432)
	return err
}

func TestChainedCapabilityVerifies(t *testing.T) {
	root := testRoot(t, rootKey)
	token := signChained(t, envKey, "env", chainedClaims(nil), envCert(t, root, nil))
	got, err := newVerifier(t, rootsConfig(root)).Verify(token, connector, "db.internal", 5432)
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != chainIssuer {
		t.Fatalf("issuer = %q", got.Issuer)
	}
}

func TestChainedCapabilityRejections(t *testing.T) {
	root, other := testRoot(t, rootKey), testRoot(t, nextRootKey)
	cert := func(mutate func(*capabilitytest.EnvironmentCert)) []byte {
		return envCert(t, root, mutate)
	}
	// bigCert has enough host names that it alone exceeds x5c's size bound,
	// in a token still within the token length limit.
	bigCert := cert(func(c *capabilitytest.EnvironmentCert) {
		for i := range 36 {
			c.Hosts = append(c.Hosts, "padding-"+strconv.Itoa(i)+".staging.traversal.com")
		}
	})
	good := cert(nil)
	stdB64 := base64.StdEncoding.EncodeToString(good)
	header := func(x5c string) string {
		return `{"alg":"ES256","typ":"traversal-capability+jwt","kid":"env","x5c":` + x5c + `}`
	}
	for _, c := range []struct {
		name  string
		token string
	}{
		{"untrusted root", signChained(t, envKey, "env", chainedClaims(nil),
			envCert(t, other, nil))},
		{"another controller host", signChained(t, envKey, "env", chainedClaims(nil),
			cert(func(c *capabilitytest.EnvironmentCert) {
				c.Hosts = []string{"edge.prod.traversal.com"}
			}))},
		{"no controller host", signChained(t, envKey, "env", chainedClaims(nil),
			cert(func(c *capabilitytest.EnvironmentCert) { c.Hosts = nil }))},
		{"expired", signChained(t, envKey, "env", chainedClaims(nil),
			cert(func(c *capabilitytest.EnvironmentCert) {
				c.NotAfter = time.Now().Add(-time.Minute)
			}))},
		{"not yet valid", signChained(t, envKey, "env", chainedClaims(nil),
			cert(func(c *capabilitytest.EnvironmentCert) {
				c.NotBefore = time.Now().Add(time.Hour)
			}))},
		{"server-auth EKU", signChained(t, envKey, "env", chainedClaims(nil),
			cert(func(c *capabilitytest.EnvironmentCert) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			}))},
		{"no digitalSignature", signChained(t, envKey, "env", chainedClaims(nil),
			cert(func(c *capabilitytest.EnvironmentCert) {
				c.KeyUsage = x509.KeyUsageKeyEncipherment
			}))},
		{"CA leaf", signChained(t, envKey, "env", chainedClaims(nil),
			cert(func(c *capabilitytest.EnvironmentCert) { c.IsCA = true }))},
		{"no issuer SAN", signChained(t, envKey, "env", chainedClaims(nil),
			cert(func(c *capabilitytest.EnvironmentCert) { c.Issuer = "" }))},
		{"foreign issuer SAN", signChained(t, envKey, "env", chainedClaims(nil),
			cert(func(c *capabilitytest.EnvironmentCert) {
				c.Issuer = "spiffe://evil.example/capability-issuer/staging"
			}))},
		{"invalid environment in issuer SAN", signChained(t, envKey, "env", chainedClaims(nil),
			cert(func(c *capabilitytest.EnvironmentCert) {
				c.Issuer = capability.IssuerURIPrefix + "Staging"
			}))},
		{"the root signs directly", signChained(t, rootKey, "env", chainedClaims(nil),
			root.DER)},
		{"claims name another environment's issuer", signChained(t, envKey, "env",
			chainedClaims(func(c *capability.Claims) { c.Issuer = capability.IssuerPrefix + "prod" }),
			good)},
		{"signed by a key the certificate does not certify", signChained(t, key, "env",
			chainedClaims(nil), good)},
		{"empty x5c", rawChained(t, header(`[]`))},
		{"three certificates", rawChained(t, header(`["`+stdB64+`","`+stdB64+`","`+stdB64+`"]`))},
		{"oversized x5c", rawChained(t,
			header(`["`+base64.StdEncoding.EncodeToString(bigCert)+`"]`))},
		{"URL-safe base64", rawChained(t, header(`["`+
			base64.RawURLEncoding.EncodeToString(good)+`"]`))},
		{"garbage certificate", signChained(t, envKey, "env", chainedClaims(nil),
			[]byte("not a certificate"))},
		{"x5c not an array", rawChained(t, header(`"`+stdB64+`"`))},
		{"duplicate x5c", rawChained(t, strings.Replace(header(`["`+stdB64+`"]`), "}",
			`,"x5c":["`+stdB64+`"]}`, 1))},
		{"case-variant x5c", rawChained(t, strings.Replace(header(`["`+stdB64+`"]`), "}",
			`,"X5C":["`+stdB64+`"]}`, 1))},
		{"no x5c and an unknown kid", func() string {
			tok, _ := capability.Sign(envKey, "env", chainedClaims(nil))
			return tok
		}()},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := verifyChained(newVerifier(t, rootsConfig(root)), c.token)
			if rawpipe.ReasonOf(err, "") != rawpipe.InvalidCapability {
				t.Fatalf("got %v, want %s", err, rawpipe.InvalidCapability)
			}
		})
	}
	oversized := rawChained(t, header(`["`+base64.StdEncoding.EncodeToString(bigCert)+`"]`))
	if len(bigCert) <= 1536 || len(oversized) > 4096 {
		t.Fatalf("oversized x5c case: %d-byte certificate in a %d-byte token", len(bigCert),
			len(oversized))
	}
}

// A connector that trusts the next root before Traversal issues from it
// accepts both, so a root rotation needs no flag day.
func TestRootRotation(t *testing.T) {
	current, next := testRoot(t, rootKey), testRoot(t, nextRootKey)
	v := newVerifier(t, rootsConfig(current, next))
	for name, root := range map[string]*capabilitytest.Root{"current": current, "next": next} {
		token := signChained(t, envKey, "env", chainedClaims(nil), envCert(t, root, nil))
		if err := verifyChained(v, token); err != nil {
			t.Fatalf("%s root: %v", name, err)
		}
	}
}

// A verifier with roots and pinned keys accepts both kinds of capability, so
// connectors move from pinned keys to roots without a cutover.
func TestPinnedKeysBesideRoots(t *testing.T) {
	root := testRoot(t, rootKey)
	cfg := rootsConfig(root)
	cfg.Keys = map[string]*ecdsa.PublicKey{"k1": &key.PublicKey, "env": &envKey.PublicKey}
	cfg.Issuer = chainIssuer
	v := newVerifier(t, cfg)

	pinned, _ := capability.Sign(key, "k1", chainedClaims(nil))
	if err := verifyChained(v, pinned); err != nil {
		t.Fatalf("pinned: %v", err)
	}
	for kid, want := range map[string]bool{
		"env":     true,  // kid names the pinned key the certificate certifies
		"unknown": true,  // kid names no pinned key: the certificate decides
		"k1":      false, // kid names another pinned key than the certified one
	} {
		token := signChained(t, envKey, kid, chainedClaims(nil), envCert(t, root, nil))
		err := verifyChained(v, token)
		if (err == nil) != want {
			t.Errorf("kid %q: %v, want accepted %v", kid, err, want)
		}
	}
	// A configured issuer constrains chained capabilities too.
	cfg.Issuer = capability.IssuerPrefix + "prod"
	cfg.Keys = map[string]*ecdsa.PublicKey{"k1": &key.PublicKey}
	token := signChained(t, envKey, "env", chainedClaims(nil), envCert(t, root, nil))
	if err := verifyChained(newVerifier(t, cfg), token); err == nil {
		t.Fatal("accepted a chained capability for another issuer than the configured one")
	}
}

// Without roots, x5c is ignored: a pinned kid still verifies as a signer
// starts sending its certificate, and anything else is refused.
func TestPinnedOnlyVerifierAndX5C(t *testing.T) {
	root := testRoot(t, rootKey)
	v := newVerifier(t, pinnedConfig())
	pinned := signChained(t, key, "k1", capabilitytest.Claims(issuer, connector, "db.internal",
		5432), envCert(t, root, nil))
	if err := verifyChained(v, pinned); err != nil {
		t.Fatalf("pinned kid with x5c: %v", err)
	}
	unknown := signChained(t, envKey, "env", chainedClaims(nil), envCert(t, root, nil))
	if err := verifyChained(v, unknown); rawpipe.ReasonOf(err, "") != rawpipe.InvalidCapability {
		t.Fatalf("unknown kid with x5c: %v, want %s", err, rawpipe.InvalidCapability)
	}
}

func TestNewVerifierConfig(t *testing.T) {
	root := testRoot(t, rootKey)
	leaf, err := x509.ParseCertificate(envCert(t, root, nil))
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]*ecdsa.PublicKey{"k1": &key.PublicKey}
	for name, cfg := range map[string]capability.VerifierConfig{
		"nothing trusted":     {Subject: "s", Issuer: issuer},
		"keys without issuer": {Subject: "s", Keys: keys},
		"no subject":          {Issuer: issuer, Keys: keys},
		"roots without host":  {Subject: "s", Roots: []*x509.Certificate{root.Certificate}},
		"non-canonical host": {Subject: "s", Roots: []*x509.Certificate{root.Certificate},
			ControllerHost: "Edge.Example.com"},
		"IP host": {Subject: "s", Roots: []*x509.Certificate{root.Certificate},
			ControllerHost: "10.0.0.1"},
		"a leaf as root": {Subject: "s", Roots: []*x509.Certificate{leaf},
			ControllerHost: chainHost},
		"nil root": {Subject: "s", Roots: []*x509.Certificate{nil}, ControllerHost: chainHost},
	} {
		if _, err := capability.NewVerifier(cfg); err == nil {
			t.Errorf("%s: NewVerifier succeeded", name)
		}
	}
	// Roots alone need no issuer.
	newVerifier(t, rootsConfig(root))
}

func TestSignChainedBounds(t *testing.T) {
	root := testRoot(t, rootKey)
	c := envCert(t, root, nil)
	for name, x5c := range map[string][][]byte{
		"none":  nil,
		"three": {c, c, c},
		"large": {make([]byte, 1537)},
	} {
		if _, err := capability.SignChained(envKey, "env", x5c, chainedClaims(nil)); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

func TestParseRootsPEM(t *testing.T) {
	current, next := testRoot(t, rootKey), testRoot(t, nextRootKey)
	block := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	bundle := block(current.DER) + block(next.DER)
	if roots, err := capability.ParseRootsPEM([]byte(bundle)); err != nil || len(roots) != 2 {
		t.Fatalf("ParseRootsPEM = %d roots, %v", len(roots), err)
	}
	for name, input := range map[string]string{
		"empty":       "",
		"junk after":  bundle + "junk",
		"public key":  "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
		"leaf":        block(envCert(t, current, nil)),
		"bad content": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
	} {
		if _, err := capability.ParseRootsPEM([]byte(input)); err == nil {
			t.Errorf("%s: ParseRootsPEM succeeded", name)
		}
	}
}
