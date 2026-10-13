// Package capability signs and verifies capabilities: short-lived ES256 JWTs
// that let one caller open raw pipes through one connector to one exact
// destination.
package capability

import (
	"bytes"
	"container/heap"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
)

const (
	Audience     = "traversal-raw-tunnel"
	IssuerPrefix = "traversal-raw-tunnel/"
	tokenType    = "traversal-capability+jwt"
	// MaxLifetime is the longest exp - iat a verifier accepts.
	MaxLifetime  = 5 * time.Minute
	maxClockSkew = 30 * time.Second
	maxTokenLen  = 4096
	// maxOpens covers an open retried on a few gateway replicas without
	// letting a leaked token open many pipes.
	maxOpens = 4
)

// Claims is a capability's payload. Every field is required.
type Claims struct {
	Issuer         string `json:"iss"`
	Audience       string `json:"aud"`
	Subject        string `json:"sub"`
	OrganizationID string `json:"organization_id"`
	IntegrationID  string `json:"integration_id"`
	ConnectorID    string `json:"connector_id"`
	ConsumerID     string `json:"consumer_id"`
	SessionID      string `json:"session_id"`
	Host           string `json:"host"`
	Port           uint16 `json:"port"`
	JTI            string `json:"jti"`
	IssuedAt       int64  `json:"iat"`
	ExpiresAt      int64  `json:"exp"`
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// reject is an invalid capability. It never quotes the token.
func reject(msg string) error { return rawpipe.Errorf(rawpipe.InvalidCapability, "%s", msg) }

// Sign returns claims as a capability signed by key under kid.
func Sign(key *ecdsa.PrivateKey, kid string, c Claims) (string, error) {
	if err := c.valid(); err != nil {
		return "", err
	}
	h, _ := json.Marshal(header{Alg: "ES256", Typ: tokenType, Kid: kid})
	p, _ := json.Marshal(c)
	input := b64(h) + "." + b64(p)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + b64(sig), nil
}

// Verifier checks capabilities and limits how often each is accepted. It is
// safe for concurrent use.
type Verifier struct {
	issuer  string
	keys    map[string]*ecdsa.PublicKey
	subject string
	now     func() time.Time

	mu    sync.Mutex
	opens map[string]int
	// expiry orders jtis by expiry, so pruning touches only expired ones;
	// capabilities live at most MaxLifetime.
	expiry jtiHeap
}

// seen is one jti and when its capability expires.
type seen struct {
	jti     string
	expires time.Time
}

// jtiHeap is a min-heap of seen, earliest expiry first (container/heap).
type jtiHeap []seen

func (h jtiHeap) Len() int           { return len(h) }
func (h jtiHeap) Less(i, j int) bool { return h[i].expires.Before(h[j].expires) }
func (h jtiHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *jtiHeap) Push(
	x any,
) {
	*h = append(*h, x.(seen))
} //nolint:forcetypeassert // heap API
func (h *jtiHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

// NewVerifier accepts capabilities from issuer, signed by one of keys (by
// kid), for subject.
func NewVerifier(issuer, subject string, keys map[string]*ecdsa.PublicKey) (*Verifier, error) {
	if issuer == "" || subject == "" || len(keys) == 0 {
		return nil, errors.New("capability: issuer, subject and a key are required")
	}
	for kid, k := range keys {
		if kid == "" || k == nil || k.Curve != elliptic.P256() {
			return nil, errors.New("capability: keys must be P-256 with a kid")
		}
	}
	return &Verifier{issuer: issuer, keys: keys, subject: subject, now: time.Now,
		opens: map[string]int{}}, nil
}

// Verify checks token for a pipe to host:port through connector and counts
// one open against it.
func (v *Verifier) Verify(token, connector, host string, port uint16) (*Claims, error) {
	c, err := v.parse(token)
	if err != nil {
		return nil, err
	}
	now := v.now()
	switch {
	case c.Issuer != v.issuer || c.Audience != Audience || c.Subject != v.subject:
		return nil, reject("wrong issuer, audience or subject")
	case now.Add(maxClockSkew).Before(time.Unix(c.IssuedAt, 0)) ||
		!now.Add(-maxClockSkew).Before(time.Unix(c.ExpiresAt, 0)):
		return nil, reject("expired or not yet valid")
	case c.ConnectorID != connector:
		return nil, rawpipe.Errorf(rawpipe.WrongConnector, "for another connector")
	case c.Host != host || c.Port != port:
		return nil, rawpipe.Errorf(rawpipe.WrongDestination, "for another destination")
	}
	if !v.take(c.JTI, time.Unix(c.ExpiresAt, 0).Add(maxClockSkew), now) {
		return nil, rawpipe.Errorf(rawpipe.Exhausted, "open limit reached")
	}
	return c, nil
}

func (v *Verifier) parse(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(token) > maxTokenLen || len(parts) != 3 {
		return nil, reject("not a compact JWS")
	}
	var h header
	if err := decode(parts[0], &h); err != nil || h.Alg != "ES256" || h.Typ != tokenType {
		return nil, reject("bad header")
	}
	key, ok := v.keys[h.Kid]
	if !ok {
		return nil, reject("unknown kid")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || len(sig) != 64 ||
		!ecdsa.Verify(
			key,
			digest[:],
			new(big.Int).SetBytes(sig[:32]),
			new(big.Int).SetBytes(sig[32:]),
		) {
		return nil, reject("bad signature")
	}
	var c Claims
	if err := decode(parts[1], &c); err != nil {
		return nil, reject("bad claims")
	}
	if err := c.valid(); err != nil {
		return nil, err
	}
	return &c, nil
}

// valid rejects claims no verifier would accept for their shape alone.
func (c *Claims) valid() error {
	for _, s := range []string{c.Issuer, c.Audience, c.Subject, c.OrganizationID,
		c.IntegrationID, c.ConnectorID, c.ConsumerID, c.SessionID, c.JTI} {
		if s == "" || len(s) > 256 {
			return reject("a claim is empty or too long")
		}
	}
	switch {
	case !strings.HasPrefix(c.Issuer, IssuerPrefix) || c.Audience != Audience:
		return reject("wrong issuer or audience")
	case !IsCanonical(c.Host) || c.Port == 0:
		return reject("destination is not canonical")
	case c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt ||
		c.ExpiresAt-c.IssuedAt > int64(MaxLifetime/time.Second):
		return reject("bad validity window")
	}
	return nil
}

func (v *Verifier) take(jti string, expires, now time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	for v.expiry.Len() > 0 && now.After(v.expiry[0].expires) {
		delete(v.opens, heap.Pop(&v.expiry).(seen).jti) //nolint:forcetypeassert // heap API
	}
	if v.opens[jti] >= maxOpens {
		return false
	}
	if v.opens[jti] == 0 {
		heap.Push(&v.expiry, seen{jti, expires})
	}
	v.opens[jti]++
	return true
}

// ParsePublicKey parses a PEM PUBLIC KEY block holding a P-256 key.
func ParsePublicKey(data []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("capability: expected a PEM PUBLIC KEY block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("capability: not a P-256 public key")
	}
	return key, nil
}

// ParseKeys reads a bundle of PUBLIC KEY blocks, each naming its kid in a
// Key-ID header, so a rotation can ship the next key beside the current one.
func ParseKeys(bundle []byte) (map[string]*ecdsa.PublicKey, error) {
	keys := map[string]*ecdsa.PublicKey{}
	for rest := bundle; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		kid := block.Headers["Key-ID"]
		key, err := ParsePublicKey(
			pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes}),
		)
		if err != nil || kid == "" || keys[kid] != nil {
			return nil, fmt.Errorf("capability: key %q needs a unique Key-ID and a P-256 key", kid)
		}
		keys[kid] = key
	}
	if len(keys) == 0 {
		return nil, errors.New("capability: no keys")
	}
	return keys, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// decode parses a JWS segment strictly: unknown fields, duplicate keys and
// keys differing only in case are refused, so one token cannot mean two
// things to two parsers.
func decode(segment string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	if err := uniqueKeys(raw); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("trailing data")
	}
	return nil
}

// uniqueKeys refuses a top-level JSON object with a key repeated, exactly or
// case-insensitively (encoding/json matches keys case-insensitively).
func uniqueKeys(raw []byte) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if _, err := d.Token(); err != nil {
		return err
	}
	seen := map[string]bool{}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return err
		}
		k := strings.ToLower(t.(string)) //nolint:forcetypeassert // object keys are strings
		if seen[k] {
			return fmt.Errorf("duplicate key %q", k)
		}
		seen[k] = true
		var skip json.RawMessage
		if err := d.Decode(&skip); err != nil {
			return err
		}
	}
	return nil
}
