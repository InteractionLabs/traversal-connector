package capability_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
)

const (
	chainHost   = "edge.staging.traversal.com"
	chainEnv    = "staging"
	chainIssuer = capability.IssuerPrefix + chainEnv
)

var (
	rootKey     = capabilitytest.Key("traversal-connector capability test key: root")
	nextRootKey = capabilitytest.Key("traversal-connector capability test key: next root")
	envKey      = capabilitytest.Key("traversal-connector capability test key: environment")
)

func testRoot(t *testing.T, key *ecdsa.PrivateKey) *capabilitytest.Root {
	t.Helper()
	root, err := capabilitytest.NewRoot(key, testNow.Add(-time.Hour), testNow.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func envCert(t *testing.T, root *capabilitytest.Root, mutate func(*capabilitytest.EnvironmentCert)) []byte {
	t.Helper()
	spec := capabilitytest.EnvironmentCert{
		Key:       &envKey.PublicKey,
		Issuer:    capability.IssuerURIPrefix + chainEnv,
		Hosts:     []string{chainHost},
		NotBefore: testNow.Add(-time.Hour),
		NotAfter:  testNow.Add(time.Hour),
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

func chainedVerifier(t *testing.T, roots ...*capabilitytest.Root) *capability.Verifier {
	t.Helper()
	certs := make([]*x509.Certificate, 0, len(roots))
	for _, r := range roots {
		certs = append(certs, r.Certificate)
	}
	v, err := capability.NewVerifier(capability.VerifierConfig{
		Roots:              certs,
		ControllerHost:     chainHost,
		AllowedSubjects:    []string{testSubject},
		Now:                func() time.Time { return testNow },
		AllowUnknownClaims: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func chainedClaims() capability.Claims {
	c := validClaims(testNow)
	c.Issuer = chainIssuer
	return c
}

func signChained(t *testing.T, key *ecdsa.PrivateKey, claims capability.Claims, x5c ...[]byte) string {
	t.Helper()
	token, err := capabilitytest.SignChained(key, "env-kid", x5c, claims)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestChainedCapabilityVerifies(t *testing.T) {
	root := testRoot(t, rootKey)
	v := chainedVerifier(t, root)
	token := signChained(t, envKey, chainedClaims(), envCert(t, root, nil))
	got, err := v.Verify(token, connectorExpected())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Claims.Issuer != chainIssuer {
		t.Fatalf("issuer = %q", got.Claims.Issuer)
	}
}

func TestChainedCapabilityRejections(t *testing.T) {
	root := testRoot(t, rootKey)
	other := testRoot(t, nextRootKey)
	cases := []struct {
		name   string
		token  func(t *testing.T) string
		want   capability.Code
		issuer string
	}{
		{"certificate from an untrusted root", func(t *testing.T) string {
			return signChained(t, envKey, chainedClaims(), envCert(t, other, nil))
		}, capability.CodeUntrustedChain, ""},
		{"certificate for another controller host", func(t *testing.T) string {
			return signChained(t, envKey, chainedClaims(), envCert(t, root,
				func(c *capabilitytest.EnvironmentCert) { c.Hosts = []string{"edge.prod.traversal.com"} }))
		}, capability.CodeUntrustedChain, ""},
		{"expired certificate", func(t *testing.T) string {
			return signChained(t, envKey, chainedClaims(), envCert(t, root,
				func(c *capabilitytest.EnvironmentCert) { c.NotAfter = testNow.Add(-time.Minute) }))
		}, capability.CodeUntrustedChain, ""},
		{"certificate not yet valid", func(t *testing.T) string {
			return signChained(t, envKey, chainedClaims(), envCert(t, root,
				func(c *capabilitytest.EnvironmentCert) { c.NotBefore = testNow.Add(time.Minute) }))
		}, capability.CodeUntrustedChain, ""},
		{"certificate without code signing", func(t *testing.T) string {
			return signChained(t, envKey, chainedClaims(), envCert(t, root,
				func(c *capabilitytest.EnvironmentCert) {
					c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
				}))
		}, capability.CodeUntrustedChain, ""},
		{"certificate that is a CA", func(t *testing.T) string {
			return signChained(t, envKey, chainedClaims(), envCert(t, root,
				func(c *capabilitytest.EnvironmentCert) { c.IsCA = true }))
		}, capability.CodeUntrustedChain, ""},
		{"certificate with no issuer", func(t *testing.T) string {
			return signChained(t, envKey, chainedClaims(), envCert(t, root,
				func(c *capabilitytest.EnvironmentCert) { c.Issuer = "" }))
		}, capability.CodeUntrustedChain, ""},
		{"certificate with a foreign issuer URI", func(t *testing.T) string {
			return signChained(t, envKey, chainedClaims(), envCert(t, root,
				func(c *capabilitytest.EnvironmentCert) { c.Issuer = "spiffe://evil.example/x" }))
		}, capability.CodeUntrustedChain, ""},
		{"claims name another environment's issuer", func(t *testing.T) string {
			c := chainedClaims()
			c.Issuer = capability.IssuerPrefix + "prod"
			return signChained(t, envKey, c, envCert(t, root, nil))
		}, capability.CodeWrongIssuer, ""},
		{"signed by a key the certificate does not certify", func(t *testing.T) string {
			return signChained(t, currentKey, chainedClaims(), envCert(t, root, nil))
		}, capability.CodeInvalidSignature, ""},
		{"the root signs a capability directly", func(t *testing.T) string {
			return signChained(t, rootKey, chainedClaims(), root.DER)
		}, capability.CodeUntrustedChain, ""},
		{"empty x5c", func(t *testing.T) string {
			payload, err := json.Marshal(chainedClaims())
			if err != nil {
				t.Fatal(err)
			}
			header := `{"alg":"ES256","kid":"k","typ":"` + capability.TokenType + `","x5c":[]}`
			token, err := capabilitytest.SignRaw(envKey, []byte(header), payload)
			if err != nil {
				t.Fatal(err)
			}
			return token
		}, capability.CodeMalformed, ""},
		{"three certificates", func(t *testing.T) string {
			c := envCert(t, root, nil)
			return signChained(t, envKey, chainedClaims(), c, c, c)
		}, capability.CodeMalformed, ""},
		{"garbage certificate", func(t *testing.T) string {
			return signChained(t, envKey, chainedClaims(), []byte("not a certificate"))
		}, capability.CodeMalformed, ""},
		{"no x5c and an unknown kid", func(t *testing.T) string {
			token, err := capabilitytest.Sign(envKey, "env-kid", chainedClaims())
			if err != nil {
				t.Fatal(err)
			}
			return token
		}, capability.CodeUnknownKey, ""},
	}
	v := chainedVerifier(t, root)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(tc.token(t), connectorExpected())
			if codeOf(err) != tc.want {
				t.Fatalf("verify = %v, want %s", err, tc.want)
			}
		})
	}
}

// A connector that trusts the next root before Traversal starts issuing from
// it accepts both, so a root rotation needs no flag day.
func TestRootRotation(t *testing.T) {
	current, next := testRoot(t, rootKey), testRoot(t, nextRootKey)
	v := chainedVerifier(t, current, next)
	for name, root := range map[string]*capabilitytest.Root{"current": current, "next": next} {
		token := signChained(t, envKey, chainedClaims(), envCert(t, root, nil))
		if _, err := v.Verify(token, connectorExpected()); err != nil {
			t.Fatalf("%s root: %v", name, err)
		}
	}
}

// A verifier with roots and pinned keys accepts both kinds of capability, so
// connectors can move from pinned keys to roots without a cutover.
func TestPinnedKeysAndRootsTogether(t *testing.T) {
	root := testRoot(t, rootKey)
	v, err := capability.NewVerifier(capability.VerifierConfig{
		Issuer:          testIssuer,
		Keys:            map[string]*ecdsa.PublicKey{currentKID: &currentKey.PublicKey},
		Roots:           []*x509.Certificate{root.Certificate},
		ControllerHost:  chainHost,
		AllowedSubjects: []string{testSubject},
		Now:             func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := capabilitytest.Sign(currentKey, currentKID, validClaims(testNow))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(pinned, connectorExpected()); err != nil {
		t.Fatalf("pinned: %v", err)
	}
	// With an Issuer configured, a chained capability must name it too.
	chained := signChained(t, envKey, chainedClaims(), envCert(t, root, nil))
	if _, err := v.Verify(chained, connectorExpected()); codeOf(err) != capability.CodeWrongIssuer {
		t.Fatalf("chained with another issuer = %v, want wrong_issuer", err)
	}
	sameIssuer := envCert(t, root, func(c *capabilitytest.EnvironmentCert) {
		c.Issuer = capability.IssuerURIPrefix + strings.TrimPrefix(testIssuer, capability.IssuerPrefix)
	})
	claims := validClaims(testNow)
	if _, err := v.Verify(signChained(t, envKey, claims, sameIssuer),
		connectorExpected()); err != nil {
		t.Fatalf("chained: %v", err)
	}
}

func TestPinnedOnlyVerifierRefusesChains(t *testing.T) {
	root := testRoot(t, rootKey)
	v := newVerifier(t, func() time.Time { return testNow })
	token := signChained(t, envKey, chainedClaims(), envCert(t, root, nil))
	if _, err := v.Verify(token, connectorExpected()); codeOf(err) != capability.CodeUntrustedChain {
		t.Fatalf("verify = %v, want untrusted_chain", err)
	}
}

func TestDuplicateX5CIsMalformed(t *testing.T) {
	root := testRoot(t, rootKey)
	header := `{"alg":"ES256","kid":"k","typ":"` + capability.TokenType +
		`","x5c":["a"],"x5c":["b"]}`
	payload, err := json.Marshal(chainedClaims())
	if err != nil {
		t.Fatal(err)
	}
	token, err := capabilitytest.SignRaw(envKey, []byte(header), payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chainedVerifier(t, root).Verify(token, connectorExpected()); codeOf(
		err,
	) != capability.CodeMalformed {
		t.Fatalf("verify = %v, want malformed", err)
	}
}

func TestNewVerifierRejectsInvalidRoots(t *testing.T) {
	root := testRoot(t, rootKey)
	leaf, err := x509.ParseCertificate(envCert(t, root, nil))
	if err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]capability.VerifierConfig{
		"no host": {Roots: []*x509.Certificate{root.Certificate},
			AllowedSubjects: []string{testSubject}},
		"non-canonical host": {Roots: []*x509.Certificate{root.Certificate},
			ControllerHost: "Edge..Test", AllowedSubjects: []string{testSubject}},
		"a leaf as root": {Roots: []*x509.Certificate{leaf}, ControllerHost: chainHost,
			AllowedSubjects: []string{testSubject}},
		"keys without issuer": {Keys: map[string]*ecdsa.PublicKey{"k": &currentKey.PublicKey},
			AllowedSubjects: []string{testSubject}},
		"nothing trusted": {AllowedSubjects: []string{testSubject}},
	} {
		if _, err := capability.NewVerifier(cfg); err == nil {
			t.Errorf("%s: NewVerifier succeeded", name)
		}
	}
}

func TestParseRootsPEM(t *testing.T) {
	current, next := testRoot(t, rootKey), testRoot(t, nextRootKey)
	bundle := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: current.DER})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: next.DER}))
	roots, err := capability.ParseRootsPEM([]byte(bundle))
	if err != nil || len(roots) != 2 {
		t.Fatalf("ParseRootsPEM = %d roots, %v", len(roots), err)
	}
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: envCert(t, current, nil)})
	for name, input := range map[string]string{
		"empty":       "",
		"junk":        bundle + "junk",
		"public key":  "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
		"leaf":        string(leaf),
		"bad content": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
	} {
		if _, err := capability.ParseRootsPEM([]byte(input)); err == nil {
			t.Errorf("%s: ParseRootsPEM succeeded", name)
		}
	}
}

func TestUntrustedChainReportsUnknownKey(t *testing.T) {
	err := error(&capability.Error{Code: capability.CodeUntrustedChain})
	var ce *capability.Error
	if !errors.As(err, &ce) || ce.OpenFailureReason().String() !=
		"RAW_OPEN_FAILURE_REASON_UNKNOWN_KEY" {
		t.Fatalf("reason = %v", ce.OpenFailureReason())
	}
}
