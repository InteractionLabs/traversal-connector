// Package capability verifies connector capabilities: short-lived ES256 JWTs
// that authorize one caller to open raw pipes through one connector to one
// exact destination.
//
// The token format is deliberately narrower than general JWT. The header has
// exactly alg "ES256", typ TokenType, and kid; the payload has exactly the
// Claims fields, each present once with the exact key spelling and type, and a
// canonical host. Anything else is rejected, so every validator reads the same
// claims from the same bytes. Validators never report the token itself.
package capability

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

const (
	// Audience is the aud claim of every connector capability.
	Audience = "traversal-raw-tunnel"
	// TokenType is the JWT typ header of every connector capability.
	TokenType = "traversal-capability+jwt"
	// Algorithm is the only accepted JWT alg header.
	Algorithm = "ES256"
	// ModePassthrough is the mode claim for RAW_PIPE_MODE_PASSTHROUGH pipes.
	ModePassthrough = "passthrough"
	// MaxTokenBytes matches RawOpen.capability's limit.
	MaxTokenBytes = 4096
	// MaxClockSkew is how far a validator's clock may differ from the signer's.
	MaxClockSkew = 30 * time.Second
	// MaxLifetime is the longest exp - iat a validator accepts.
	MaxLifetime = 5 * time.Minute
	// MaxOpensPerToken is how many pipes one capability may open per validator.
	MaxOpensPerToken = 64
	// maxClaimBytes bounds every string claim except host.
	maxClaimBytes = 256
)

// Claims is a capability's payload. Every field is required.
type Claims struct {
	Issuer         string `json:"iss"`
	Audience       string `json:"aud"`
	Subject        string `json:"sub"`
	OrganizationID string `json:"organization_id"`
	IntegrationID  string `json:"integration_id"`
	ConnectorID    string `json:"connector_id"`
	Host           string `json:"host"`
	Port           uint16 `json:"port"`
	Mode           string `json:"mode"`
	ConsumerID     string `json:"consumer_id"`
	TrafficClass   string `json:"traffic_class"`
	SessionID      string `json:"session_id"`
	JTI            string `json:"jti"`
	IssuedAt       int64  `json:"iat"`
	ExpiresAt      int64  `json:"exp"`
}

// Header is a capability's JOSE header.
type Header struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

var (
	claimKeys  = jsonKeys(Claims{})
	headerKeys = jsonKeys(Header{})
)

// Code classifies a verification failure.
type Code string

// Verification failure codes.
const (
	CodeMalformed        Code = "malformed"
	CodeUnknownKey       Code = "unknown_key"
	CodeInvalidSignature Code = "invalid_signature"
	CodeWrongIssuer      Code = "wrong_issuer"
	CodeWrongAudience    Code = "wrong_audience"
	CodeNotYetValid      Code = "not_yet_valid"
	CodeExpired          Code = "expired"
	CodeLifetimeTooLong  Code = "lifetime_too_long"
	CodeForbiddenSubject Code = "forbidden_subject"
	CodeWrongTenant      Code = "wrong_organization"
	CodeWrongConnector   Code = "wrong_connector"
	CodeWrongDestination Code = "wrong_destination"
	CodeUnsupportedMode  Code = "unsupported_mode"
	CodeExhausted        Code = "capability_exhausted"
)

// Error reports why a capability was rejected. It never contains the token.
type Error struct {
	Code   Code
	detail string
}

func (e *Error) Error() string {
	return fmt.Sprintf("capability: %s: %s", e.Code, e.detail)
}

// OpenFailureReason maps the failure to the reason sent in RawOpenError.
func (e *Error) OpenFailureReason() pb.RawOpenFailureReason {
	switch e.Code {
	case CodeUnknownKey:
		return pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_UNKNOWN_KEY
	case CodeWrongAudience:
		return pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_WRONG_AUDIENCE
	case CodeNotYetValid, CodeExpired:
		return pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPABILITY_EXPIRED
	case CodeForbiddenSubject, CodeWrongTenant:
		return pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_FORBIDDEN
	case CodeWrongConnector:
		return pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_WRONG_CONNECTOR
	case CodeWrongDestination:
		return pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_WRONG_DESTINATION
	case CodeUnsupportedMode:
		return pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_UNSUPPORTED_MODE
	case CodeExhausted:
		return pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPABILITY_EXHAUSTED
	default:
		return pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_INVALID_CAPABILITY
	}
}

func fail(code Code, detail string) *Error {
	return &Error{Code: code, detail: detail}
}

// ModeClaim returns the mode claim for a pipe mode, or false if capabilities
// cannot authorize it.
func ModeClaim(mode pb.RawPipeMode) (string, bool) {
	if mode == pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH {
		return ModePassthrough, true
	}
	return "", false
}

// VerifierConfig configures a Verifier.
type VerifierConfig struct {
	// Issuer is the exact iss claim to accept, traversal-raw-tunnel/<env>.
	Issuer string
	// Keys are the trusted public keys by kid: the current key and, during a
	// rotation, the next one. Every key must be P-256.
	Keys map[string]*ecdsa.PublicKey
	// AllowedSubjects are the sub claims permitted to open pipes.
	AllowedSubjects []string
	// Now defaults to time.Now.
	Now func() time.Time
}

// Verifier checks capabilities and counts opens per capability. It is safe for
// concurrent use.
type Verifier struct {
	issuer   string
	keys     map[string]*ecdsa.PublicKey
	subjects map[string]bool
	now      func() time.Time
	opens    *openCounter
}

// NewVerifier validates cfg and returns a Verifier.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("capability: issuer is required")
	}
	if len(cfg.Keys) == 0 {
		return nil, errors.New("capability: at least one key is required")
	}
	keys := make(map[string]*ecdsa.PublicKey, len(cfg.Keys))
	for kid, key := range cfg.Keys {
		if kid == "" || key == nil || key.Curve != elliptic.P256() {
			return nil, errors.New("capability: keys must be P-256 with a kid")
		}
		keys[kid] = key
	}
	if len(cfg.AllowedSubjects) == 0 {
		return nil, errors.New("capability: at least one allowed subject is required")
	}
	subjects := make(map[string]bool, len(cfg.AllowedSubjects))
	for _, s := range cfg.AllowedSubjects {
		subjects[s] = true
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Verifier{
		issuer:   cfg.Issuer,
		keys:     keys,
		subjects: subjects,
		now:      now,
		opens:    newOpenCounter(),
	}, nil
}

// Expected is what the validator already knows about the open being
// authorized. Host must be the requested host as received; a non-canonical
// request never matches.
type Expected struct {
	ConnectorID string
	// OrganizationID is the tenant that owns ConnectorID. Leave it empty only
	// where the validator cannot know its tenant, as on the connector, whose
	// identity is already bound to one tenant by its credentials.
	OrganizationID string
	Host           string
	Port           uint16
	Mode           pb.RawPipeMode
}

// Verified is an accepted capability.
type Verified struct {
	Claims Claims
	// ClockSkew is how far the signer's clock appeared to be ahead of this
	// validator's when the capability was issued, from iat. It is negative
	// when the signer is behind, and includes the capability's age in transit.
	ClockSkew time.Duration
}

// Verify checks token against want and, if it is valid, counts one open
// against the capability. Opens are counted only for tokens that pass every
// other check, so rejected attempts cannot exhaust a capability.
func (v *Verifier) Verify(token string, want Expected) (*Verified, error) {
	claims, err := v.parse(token)
	if err != nil {
		return nil, err
	}
	now := v.now()
	if err := v.checkClaims(claims, want, now); err != nil {
		return nil, err
	}
	if !v.opens.take(claims.JTI, time.Unix(claims.ExpiresAt, 0).Add(MaxClockSkew), now) {
		return nil, fail(CodeExhausted, "open limit reached")
	}
	return &Verified{
		Claims:    *claims,
		ClockSkew: time.Unix(claims.IssuedAt, 0).Sub(now),
	}, nil
}

// parse checks the token's structure and signature and returns its claims.
func (v *Verifier) parse(token string) (*Claims, error) {
	if len(token) > MaxTokenBytes {
		return nil, fail(CodeMalformed, "token too long")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fail(CodeMalformed, "token is not a compact JWS")
	}
	var header Header
	if err := decodeSegment(parts[0], headerKeys, &header); err != nil {
		return nil, fail(CodeMalformed, "header: "+err.Error())
	}
	if header.Algorithm != Algorithm || header.Type != TokenType {
		return nil, fail(CodeMalformed, "unsupported alg or typ")
	}
	if replacement(header.Algorithm) || replacement(header.KeyID) || replacement(header.Type) {
		return nil, fail(CodeMalformed, "header: invalid text")
	}
	key, ok := v.keys[header.KeyID]
	if !ok {
		return nil, fail(CodeUnknownKey, "untrusted kid")
	}
	sig, err := decodeBase64(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, fail(CodeInvalidSignature, "signature is not 64-byte r||s")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return nil, fail(CodeInvalidSignature, "signature does not verify")
	}
	var claims Claims
	if err := decodeSegment(parts[1], claimKeys, &claims); err != nil {
		return nil, fail(CodeMalformed, "claims: "+err.Error())
	}
	return &claims, nil
}

func (v *Verifier) checkClaims(c *Claims, want Expected, now time.Time) error {
	if err := checkShape(c); err != nil {
		return err
	}
	switch {
	case c.Issuer != v.issuer:
		return fail(CodeWrongIssuer, "unexpected iss")
	case c.Audience != Audience:
		return fail(CodeWrongAudience, "unexpected aud")
	case c.ExpiresAt-c.IssuedAt > int64(MaxLifetime/time.Second):
		return fail(CodeLifetimeTooLong, "exp - iat exceeds the maximum lifetime")
	case now.Add(MaxClockSkew).Before(time.Unix(c.IssuedAt, 0)):
		return fail(CodeNotYetValid, "iat is in the future")
	case !now.Add(-MaxClockSkew).Before(time.Unix(c.ExpiresAt, 0)):
		return fail(CodeExpired, "exp has passed")
	case !v.subjects[c.Subject]:
		return fail(CodeForbiddenSubject, "sub may not open pipes")
	case want.OrganizationID != "" && c.OrganizationID != want.OrganizationID:
		return fail(CodeWrongTenant, "organization_id does not own the connector")
	case c.ConnectorID != want.ConnectorID:
		return fail(CodeWrongConnector, "connector_id names another connector")
	case c.Host != want.Host || c.Port != want.Port:
		return fail(CodeWrongDestination, "destination differs from host and port")
	}
	if mode, ok := ModeClaim(want.Mode); !ok || c.Mode != mode {
		return fail(CodeUnsupportedMode, "mode is not authorized")
	}
	return nil
}

// checkShape rejects claims no signer would produce: empty or oversized
// values, a non-canonical host, or an inverted validity window.
func checkShape(c *Claims) error {
	for _, s := range []string{
		c.Issuer, c.Audience, c.Subject, c.OrganizationID, c.IntegrationID, c.ConnectorID,
		c.Mode, c.ConsumerID, c.TrafficClass, c.SessionID, c.JTI,
	} {
		if s == "" || len(s) > maxClaimBytes || replacement(s) {
			return fail(CodeMalformed, "a string claim is empty or too long")
		}
	}
	if canonical, err := CanonicalHost(c.Host); err != nil || canonical != c.Host {
		return fail(CodeMalformed, "host is not canonical")
	}
	if c.Port == 0 {
		return fail(CodeMalformed, "port is zero")
	}
	if c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt {
		return fail(CodeMalformed, "invalid validity window")
	}
	return nil
}

// decodeSegment decodes one base64url JSON segment into v. The object must
// contain exactly the keys in want, each once and spelled exactly, because
// encoding/json would otherwise accept duplicates (last wins) and match keys
// case-insensitively, letting two parsers read different claims.
func decodeSegment(segment string, want map[string]bool, v any) error {
	raw, err := decodeBase64(segment)
	if err != nil {
		return errors.New("invalid base64url")
	}
	// encoding/json silently replaces invalid UTF-8.
	if !utf8.Valid(raw) {
		return errors.New("invalid UTF-8")
	}
	fields := make(map[string]json.RawMessage, len(want))
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return errors.New("not a JSON object")
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return errors.New("invalid JSON")
		}
		key, _ := tok.(string)
		if !want[key] {
			return errors.New("unexpected field")
		}
		if _, dup := fields[key]; dup {
			return errors.New("duplicate field")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return errors.New("invalid JSON")
		}
		fields[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return errors.New("invalid JSON")
	}
	if _, err := dec.Token(); err == nil {
		return errors.New("trailing data")
	}
	if len(fields) != len(want) {
		return errors.New("missing field")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return errors.New("field has the wrong type")
	}
	return nil
}

func decodeBase64(s string) ([]byte, error) {
	// Strict mode still ignores CR and LF, so one token would have many
	// spellings and a validator in another language would reject it.
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("contains a line break")
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

// replacement reports whether s contains U+FFFD. encoding/json decodes an
// unpaired surrogate escape to that rune, and the UTF-8 check on the raw
// segment cannot see escapes.
func replacement(s string) bool {
	return strings.ContainsRune(s, utf8.RuneError)
}

// jsonKeys returns the JSON keys of a struct's fields.
func jsonKeys(v any) map[string]bool {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		panic(err)
	}
	keys := make(map[string]bool, len(fields))
	for k := range fields {
		keys[k] = true
	}
	return keys
}

// ParsePublicKeyPEM parses a PEM "PUBLIC KEY" block, the form KMS
// GetPublicKey returns once PEM-encoded, into a P-256 key.
func ParsePublicKeyPEM(data []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("capability: expected a PEM PUBLIC KEY block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("capability: parse public key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("capability: public key is not ECDSA P-256")
	}
	return key, nil
}

// openCounter enforces MaxOpensPerToken per jti until the capability expires.
type openCounter struct {
	mu        sync.Mutex
	entries   map[string]*openCount
	lastSweep time.Time
}

type openCount struct {
	opens   int
	expires time.Time
}

// sweepInterval bounds how often expired entries are scanned for. Entries
// exist only for validly signed capabilities, so the map is bounded by the
// signing rate times MaxLifetime.
const sweepInterval = 30 * time.Second

func newOpenCounter() *openCounter {
	return &openCounter{entries: make(map[string]*openCount)}
}

func (c *openCounter) take(jti string, expires, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.lastSweep) >= sweepInterval {
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		}
		c.lastSweep = now
	}
	e := c.entries[jti]
	if e == nil {
		e = &openCount{expires: expires}
		c.entries[jti] = e
	}
	if e.opens >= MaxOpensPerToken {
		return false
	}
	e.opens++
	return true
}
