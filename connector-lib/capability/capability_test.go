package capability_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

const (
	testIssuer  = "traversal-raw-tunnel/test"
	testSubject = "platform-conformance"
	currentKID  = "test-key-current"
	nextKID     = "test-key-next"
)

var (
	currentKey = capabilitytest.Key("traversal-connector capability test key: current")
	nextKey    = capabilitytest.Key("traversal-connector capability test key: next")
	testNow    = time.Unix(1_790_000_000, 0)
)

func expected() capability.Expected {
	return capability.Expected{
		ConnectorID:    "connector-1",
		OrganizationID: "org-1",
		IntegrationID:  "integration-1",
		ConsumerID:     "platform-conformance",
		SessionID:      "session-1",
		TrafficClass:   "standard",
		Host:           "db.internal",
		Port:           5432,
		Mode:           pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH,
	}
}

// connectorExpected is what a connector verifier can bind: its own id and the
// requested destination/mode. Optional caller/tenant claims stay empty.
func connectorExpected() capability.Expected {
	return capability.Expected{
		ConnectorID: "connector-1",
		Host:        "db.internal",
		Port:        5432,
		Mode:        pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH,
	}
}

func validClaims(now time.Time) capability.Claims {
	iat := now.Add(-10 * time.Second).Unix()
	return capability.Claims{
		Issuer:         testIssuer,
		Audience:       capability.Audience,
		Subject:        testSubject,
		OrganizationID: "org-1",
		IntegrationID:  "integration-1",
		ConnectorID:    "connector-1",
		Host:           "db.internal",
		Port:           5432,
		Mode:           capability.ModePassthrough,
		ConsumerID:     "platform-conformance",
		TrafficClass:   "standard",
		SessionID:      "session-1",
		JTI:            "jti-1",
		IssuedAt:       iat,
		ExpiresAt:      iat + 120,
	}
}

func newVerifier(t *testing.T, now func() time.Time) *capability.Verifier {
	t.Helper()
	v, err := capability.NewVerifier(capability.VerifierConfig{
		Issuer: testIssuer,
		Keys: map[string]*ecdsa.PublicKey{
			currentKID: &currentKey.PublicKey,
			nextKID:    &nextKey.PublicKey,
		},
		AllowedSubjects: []string{testSubject},
		Now:             now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func sign(t testing.TB, c capability.Claims) string {
	t.Helper()
	token, err := capabilitytest.Sign(currentKey, currentKID, c)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func codeOf(err error) capability.Code {
	var capErr *capability.Error
	if errors.As(err, &capErr) {
		return capErr.Code
	}
	return ""
}

func TestVerifyReportsClaimsAndSkew(t *testing.T) {
	v := newVerifier(t, func() time.Time { return testNow })
	got, err := v.Verify(sign(t, validClaims(testNow)), expected())
	if err != nil {
		t.Fatal(err)
	}
	if got.Claims != validClaims(testNow) {
		t.Fatalf("claims = %+v", got.Claims)
	}
	if got.ClockSkew != -10*time.Second {
		t.Fatalf("skew = %v, want -10s", got.ClockSkew)
	}
}

func TestVerifyAllowsThirtySecondsOfSkew(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*capability.Claims)
		want   capability.Code
	}{
		{"issued 30s ahead", func(c *capability.Claims) {
			c.IssuedAt, c.ExpiresAt = testNow.Unix()+30, testNow.Unix()+150
		}, ""},
		{"issued 31s ahead", func(c *capability.Claims) {
			c.IssuedAt, c.ExpiresAt = testNow.Unix()+31, testNow.Unix()+151
		}, capability.CodeNotYetValid},
		{"expired 29s ago", func(c *capability.Claims) {
			c.IssuedAt, c.ExpiresAt = testNow.Unix()-149, testNow.Unix()-29
		}, ""},
		{"expired 30s ago", func(c *capability.Claims) {
			c.IssuedAt, c.ExpiresAt = testNow.Unix()-150, testNow.Unix()-30
		}, capability.CodeExpired},
		{"five minute lifetime", func(c *capability.Claims) {
			c.ExpiresAt = c.IssuedAt + 300
		}, ""},
		{"longer lifetime", func(c *capability.Claims) {
			c.ExpiresAt = c.IssuedAt + 301
		}, capability.CodeLifetimeTooLong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validClaims(testNow)
			tc.mutate(&c)
			_, err := newVerifier(
				t,
				func() time.Time { return testNow },
			).Verify(sign(t, c), expected())
			if got := codeOf(err); got != tc.want {
				t.Fatalf("Verify = %v, want code %q", err, tc.want)
			}
		})
	}
}

func TestOpenLimitPerCapability(t *testing.T) {
	now := testNow
	v := newVerifier(t, func() time.Time { return now })
	token := sign(t, validClaims(testNow))

	// Rejected attempts must not spend the capability's opens.
	wrong := expected()
	wrong.Port = 1
	for range 100 {
		if _, err := v.Verify(token, wrong); codeOf(err) != capability.CodeWrongDestination {
			t.Fatalf("Verify = %v", err)
		}
	}

	var ok, exhausted atomic.Int32
	var wg sync.WaitGroup
	for range capability.MaxOpensPerToken + 36 {
		wg.Go(func() {
			_, err := v.Verify(token, expected())
			switch codeOf(err) {
			case "":
				ok.Add(1)
			case capability.CodeExhausted:
				exhausted.Add(1)
			default:
				t.Errorf("Verify = %v", err)
			}
		})
	}
	wg.Wait()
	if ok.Load() != capability.MaxOpensPerToken || exhausted.Load() != 36 {
		t.Fatalf("%d opens allowed and %d refused", ok.Load(), exhausted.Load())
	}

	other := validClaims(testNow)
	other.JTI = "jti-2"
	if _, err := v.Verify(sign(t, other), expected()); err != nil {
		t.Fatalf("another capability was limited: %v", err)
	}
}

func TestOpenCountsExpireWithTheCapability(t *testing.T) {
	now := testNow
	v := newVerifier(t, func() time.Time { return now })
	c := validClaims(testNow)
	token := sign(t, c)
	for range capability.MaxOpensPerToken {
		if _, err := v.Verify(token, expected()); err != nil {
			t.Fatal(err)
		}
	}
	// A signer never reuses a jti, but if one did after the old capability
	// expired, the new capability starts with a fresh count.
	now = time.Unix(c.ExpiresAt, 0).Add(capability.MaxClockSkew + time.Minute)
	reissued := validClaims(now)
	if _, err := v.Verify(sign(t, reissued), expected()); err != nil {
		t.Fatalf("stale count survived expiry: %v", err)
	}
}

func TestExpectedSubjectBindsTheAuthenticatedCaller(t *testing.T) {
	const otherSubject = "other-signer"
	v, err := capability.NewVerifier(capability.VerifierConfig{
		Issuer: testIssuer,
		Keys: map[string]*ecdsa.PublicKey{
			currentKID: &currentKey.PublicKey,
		},
		AllowedSubjects: []string{testSubject, otherSubject},
		Now:             func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	claimsA := validClaims(testNow)
	claimsB := validClaims(testNow)
	claimsB.Subject = otherSubject
	claimsB.JTI = "jti-b"
	tokenA := sign(t, claimsA)
	tokenB := sign(t, claimsB)
	base := connectorExpected()

	if _, err = v.Verify(tokenB, base); err != nil {
		t.Fatalf("empty subject rejected an allowlisted token: %v", err)
	}
	wantA := base
	wantA.Subject = testSubject
	if _, err = v.Verify(tokenA, wantA); err != nil {
		t.Fatalf("matching subject rejected: %v", err)
	}
	_, err = v.Verify(tokenB, wantA)
	if got := codeOf(err); got != capability.CodeForbidden {
		t.Fatalf("other allowlisted subject = %v, want %s", err, capability.CodeForbidden)
	}
}

func TestOptionalExpectedClaims(t *testing.T) {
	token := sign(t, validClaims(testNow))
	base := connectorExpected()

	t.Run("empty optional does not constrain", func(t *testing.T) {
		if _, err := newVerifier(t, func() time.Time { return testNow }).Verify(token, base); err != nil {
			t.Fatalf("Verify = %v", err)
		}
	})

	for _, tc := range []struct {
		name string
		set  func(*capability.Expected)
		want capability.Code
	}{
		{"organization mismatch", func(e *capability.Expected) { e.OrganizationID = "org-2" },
			capability.CodeWrongTenant},
		{"organization match", func(e *capability.Expected) { e.OrganizationID = "org-1" }, ""},
		{"integration mismatch", func(e *capability.Expected) { e.IntegrationID = "other" },
			capability.CodeForbidden},
		{"integration match", func(e *capability.Expected) { e.IntegrationID = "integration-1" }, ""},
		{"consumer mismatch", func(e *capability.Expected) { e.ConsumerID = "other" },
			capability.CodeForbidden},
		{"consumer match", func(e *capability.Expected) { e.ConsumerID = "platform-conformance" }, ""},
		{"session mismatch", func(e *capability.Expected) { e.SessionID = "other" },
			capability.CodeForbidden},
		{"session match", func(e *capability.Expected) { e.SessionID = "session-1" }, ""},
		{"traffic class mismatch", func(e *capability.Expected) { e.TrafficClass = "other" },
			capability.CodeForbidden},
		{"traffic class match", func(e *capability.Expected) { e.TrafficClass = "standard" }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := base
			tc.set(&want)
			_, err := newVerifier(t, func() time.Time { return testNow }).Verify(token, want)
			if got := codeOf(err); got != tc.want {
				t.Fatalf("Verify = %v, want code %q", err, tc.want)
			}
		})
	}
}

func TestStructuralRejections(t *testing.T) {
	valid := sign(t, validClaims(testNow))
	parts := strings.Split(valid, ".")
	other := validClaims(testNow)
	other.JTI = "jti-9"
	otherPayload := strings.Split(sign(t, other), ".")[1]
	for _, tc := range []struct {
		name  string
		token string
		want  capability.Code
	}{
		{"empty", "", capability.CodeMalformed},
		{"two segments", parts[0] + "." + parts[1], capability.CodeMalformed},
		{"four segments", valid + ".x", capability.CodeMalformed},
		{"oversized", valid + strings.Repeat("A", capability.MaxTokenBytes), capability.CodeMalformed},
		{"padded base64", parts[0] + "=." + parts[1] + "." + parts[2], capability.CodeMalformed},
		{"standard base64 alphabet", strings.ReplaceAll(parts[0], "-", "+") + "+." + parts[1] +
			"." + parts[2], capability.CodeMalformed},
		{"truncated signature", parts[0] + "." + parts[1] + "." + parts[2][:40],
			capability.CodeInvalidSignature},
		{"payload from another token", parts[0] + "." + otherPayload + "." + parts[2],
			capability.CodeInvalidSignature},
		{"line break in signature", parts[0] + "." + parts[1] + "." +
			parts[2][:8] + "\r\n" + parts[2][8:], capability.CodeInvalidSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newVerifier(
				t,
				func() time.Time { return testNow },
			).Verify(tc.token, expected())
			if got := codeOf(err); got != tc.want {
				t.Fatalf("Verify = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRejectsUnpairedSurrogate(t *testing.T) {
	payload, err := json.Marshal(validClaims(testNow))
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(payload), `"jti-1"`, `"jti-\ud800"`, 1)
	token, err := capabilitytest.SignRaw(currentKey, []byte(
		`{"alg":"ES256","kid":"`+currentKID+`","typ":"`+capability.TokenType+`"}`),
		[]byte(edited))
	if err != nil {
		t.Fatal(err)
	}
	_, err = newVerifier(t, func() time.Time { return testNow }).Verify(token, expected())
	if codeOf(err) != capability.CodeMalformed {
		t.Fatalf("Verify = %v, want malformed", err)
	}
}

func TestErrorsNeverContainTheToken(t *testing.T) {
	v := newVerifier(t, func() time.Time { return testNow })
	c := validClaims(testNow)
	c.Port = 1
	token := sign(t, c)
	_, err := v.Verify(token, expected())
	if err == nil {
		t.Fatal("Verify succeeded")
	}
	for _, part := range strings.Split(token, ".") {
		if strings.Contains(err.Error(), part) {
			t.Fatalf("error %q contains token material", err)
		}
	}
}

func TestOpenFailureReasons(t *testing.T) {
	for code, want := range map[capability.Code]pb.RawOpenFailureReason{
		capability.CodeMalformed:        pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_INVALID_CAPABILITY,
		capability.CodeInvalidSignature: pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_INVALID_CAPABILITY,
		capability.CodeWrongIssuer:      pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_INVALID_CAPABILITY,
		capability.CodeLifetimeTooLong:  pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_INVALID_CAPABILITY,
		capability.CodeUnknownKey:       pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_UNKNOWN_KEY,
		capability.CodeWrongAudience:    pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_WRONG_AUDIENCE,
		capability.CodeNotYetValid:      pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPABILITY_EXPIRED,
		capability.CodeExpired:          pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPABILITY_EXPIRED,
		capability.CodeForbiddenSubject: pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_FORBIDDEN,
		capability.CodeWrongTenant:      pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_FORBIDDEN,
		capability.CodeForbidden:        pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_FORBIDDEN,
		capability.CodeWrongConnector:   pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_WRONG_CONNECTOR,
		capability.CodeWrongDestination: pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_WRONG_DESTINATION,
		capability.CodeUnsupportedMode:  pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_UNSUPPORTED_MODE,
		capability.CodeExhausted:        pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPABILITY_EXHAUSTED,
	} {
		if got := (&capability.Error{Code: code}).OpenFailureReason(); got != want {
			t.Errorf("%s maps to %v, want %v", code, got, want)
		}
	}
}

func TestNewVerifierRejectsInvalidConfig(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]*ecdsa.PublicKey{currentKID: &currentKey.PublicKey}
	subjects := []string{testSubject}
	for _, cfg := range []capability.VerifierConfig{
		{Keys: keys, AllowedSubjects: subjects},
		{Issuer: testIssuer, AllowedSubjects: subjects},
		{Issuer: testIssuer, Keys: keys},
		{Issuer: testIssuer, AllowedSubjects: subjects,
			Keys: map[string]*ecdsa.PublicKey{"": &currentKey.PublicKey}},
		{Issuer: testIssuer, AllowedSubjects: subjects,
			Keys: map[string]*ecdsa.PublicKey{"p384": &p384.PublicKey}},
	} {
		if _, err := capability.NewVerifier(cfg); err == nil {
			t.Errorf("NewVerifier(%+v) succeeded", cfg)
		}
	}
}

func TestParsePublicKeyPEM(t *testing.T) {
	der, err := x509.MarshalPKIXPublicKey(&currentKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := capability.ParsePublicKeyPEM(pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: der,
	}))
	if err != nil || !key.Equal(&currentKey.PublicKey) {
		t.Fatalf("ParsePublicKeyPEM = %v, %v", key, err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	for _, input := range [][]byte{
		nil,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("junk")}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der384}),
	} {
		if _, err := capability.ParsePublicKeyPEM(input); err == nil {
			t.Errorf("ParsePublicKeyPEM(%q) succeeded", input)
		}
	}
}

// FuzzVerify checks that arbitrary input is rejected with a typed error and
// never panics.
func FuzzVerify(f *testing.F) {
	f.Add(sign(f, validClaims(testNow)))
	for _, tc := range tokenCases {
		f.Add(tc.sign(f, validClaims(testNow)))
	}
	f.Fuzz(func(t *testing.T, token string) {
		v := newVerifier(t, func() time.Time { return testNow })
		if _, err := v.Verify(token, expected()); err != nil && codeOf(err) == "" {
			t.Fatalf("untyped error %v", err)
		}
	})
}

func TestUnknownClaimIsIgnoredOnlyWhenAllowed(t *testing.T) {
	payload, err := json.Marshal(validClaims(testNow))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	fields["agent_id"] = json.RawMessage(`"agent-1"`)
	extra, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	header, err := json.Marshal(capability.Header{
		Algorithm: capability.Algorithm,
		KeyID:     currentKID,
		Type:      capability.TokenType,
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := capabilitytest.SignRaw(currentKey, header, extra)
	if err != nil {
		t.Fatal(err)
	}
	strict := newVerifier(t, func() time.Time { return testNow })
	if _, err := strict.Verify(token, connectorExpected()); codeOf(err) != capability.CodeMalformed {
		t.Fatalf("strict verify = %v, want malformed", err)
	}
	loose, err := capability.NewVerifier(capability.VerifierConfig{
		Issuer: testIssuer,
		Keys: map[string]*ecdsa.PublicKey{
			currentKID: &currentKey.PublicKey,
		},
		AllowedSubjects:    []string{testSubject},
		Now:                func() time.Time { return testNow },
		AllowUnknownClaims: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := loose.Verify(token, connectorExpected())
	if err != nil {
		t.Fatal(err)
	}
	if got.Claims != validClaims(testNow) {
		t.Fatalf("claims = %+v", got.Claims)
	}
	delete(fields, "connector_id")
	missing, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	broken, err := capabilitytest.SignRaw(currentKey, header, missing)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loose.Verify(broken, connectorExpected()); codeOf(err) != capability.CodeMalformed {
		t.Fatalf("missing claim = %v, want malformed", err)
	}
}

func TestModeClaim(t *testing.T) {
	if got, ok := capability.ModeClaim(pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH); !ok ||
		got != capability.ModePassthrough {
		t.Fatalf("ModeClaim(passthrough) = %q, %v", got, ok)
	}
	if _, ok := capability.ModeClaim(pb.RawPipeMode_RAW_PIPE_MODE_UNSPECIFIED); ok {
		t.Fatal("ModeClaim(unspecified) succeeded")
	}
}
