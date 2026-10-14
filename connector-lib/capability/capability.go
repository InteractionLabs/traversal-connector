// Package capability signs and verifies capabilities: short-lived ES256 JWTs
// that let one caller open raw pipes through one connector to one exact
// destination.
//
// A capability says who may reach which host:port, nothing about how: how a
// pipe behaves comes from the connector's own configuration. So claims decode
// leniently (RFC 7519 section 4): a claim this package does not know is
// ignored, which lets Traversal add informational claims without a connector
// release. That is safe because nothing a capability adds can widen what a
// connector allows: its dial policy and the customer's redaction config bound
// every pipe, whatever the token says. Everything else stays strict, as
// package jws parses every token: the JWS header holds exactly alg, typ, kid
// and optionally x5c; every known claim must be present with its JSON type;
// keys may not repeat, exactly or by case, anywhere in either segment; and
// nothing may trail the JSON.
package capability

import (
	"container/heap"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/jws"
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
	// maxOpens covers an open retried on a few edge controller replicas without
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

// reject is an invalid capability. It never quotes the token.
func reject(msg string) error { return rawpipe.Errorf(rawpipe.InvalidCapability, "%s", msg) }

// Sign returns claims as a capability signed by key under kid.
func Sign(key *ecdsa.PrivateKey, kid string, c Claims) (string, error) {
	return sign(key, jws.Header{Typ: tokenType, Kid: kid}, c)
}

// SignChained is Sign that also sends x5c, the DER certificate chain of key
// (its environment certificate first, then any intermediate), so verifiers
// that pin only Traversal's roots trust it. The leaf must certify key and
// name the issuer of c; SignChained checks only x5c's bounds.
func SignChained(key *ecdsa.PrivateKey, kid string, x5c [][]byte, c Claims) (string, error) {
	total := 0
	chain := make([]string, len(x5c))
	for i, der := range x5c {
		total += len(der)
		chain[i] = base64.StdEncoding.EncodeToString(der)
	}
	if len(x5c) == 0 || len(x5c) > maxChainCerts || total > maxChainBytes {
		return "", fmt.Errorf("capability: x5c must be 1 to %d certificates, at most %d bytes",
			maxChainCerts, maxChainBytes)
	}
	return sign(key, jws.Header{Typ: tokenType, Kid: kid, X5C: chain}, c)
}

func sign(key *ecdsa.PrivateKey, h jws.Header, c Claims) (string, error) {
	if err := c.valid(); err != nil {
		return "", err
	}
	return jws.Sign(key, h, c)
}

// Verifier checks capabilities and limits how often each is accepted. It is
// safe for concurrent use.
type Verifier struct {
	issuer  string
	keys    map[string]*ecdsa.PublicKey
	chains  *chains
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

// VerifierConfig says which capabilities a Verifier trusts: those signed by
// a pinned key, or by a key an environment certificate certifies under a
// pinned root (chain.go), or either while moving from keys to roots.
type VerifierConfig struct {
	// Issuer is the iss claim to accept, traversal-raw-tunnel/<env>.
	// Required with Keys. With Roots alone it may be empty: a chained
	// capability's issuer is the one its certificate names. Set, it
	// constrains chained capabilities too.
	Issuer string
	// Subject is the sub claim to accept. Required.
	Subject string
	// Keys are the pinned P-256 keys by kid: the current one and, during a
	// rotation, the next.
	Keys map[string]*ecdsa.PublicKey
	// Roots are the pinned capability roots: the current one and, during a
	// root rotation, the next.
	Roots []*x509.Certificate
	// ControllerHost is the host this verifier's connector dials for its
	// controller. Required with Roots: an environment certificate must name
	// it, which binds a chained capability to this connector's environment.
	ControllerHost string
}

// NewVerifier returns a Verifier for cfg. At least one key or root is
// required.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	switch {
	case cfg.Subject == "":
		return nil, errors.New("capability: a subject is required")
	case len(cfg.Keys) == 0 && len(cfg.Roots) == 0:
		return nil, errors.New("capability: a key or a root is required")
	case len(cfg.Keys) > 0 && cfg.Issuer == "":
		return nil, errors.New("capability: an issuer is required with keys")
	}
	for kid, k := range cfg.Keys {
		if kid == "" || k == nil || k.Curve != elliptic.P256() {
			return nil, errors.New("capability: keys must be P-256 with a kid")
		}
	}
	v := &Verifier{issuer: cfg.Issuer, keys: cfg.Keys, subject: cfg.Subject, now: time.Now,
		opens: map[string]int{}}
	if len(cfg.Roots) > 0 {
		var err error
		if v.chains, err = newChains(cfg.Roots, cfg.ControllerHost); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// Verify checks token for a pipe to host:port through connector and counts
// one open against it.
func (v *Verifier) Verify(token, connector, host string, port uint16) (*Claims, error) {
	now := v.now()
	c, issuer, err := v.parse(token, now)
	if err != nil {
		return nil, err
	}
	switch {
	case c.Issuer != issuer || v.issuer != "" && c.Issuer != v.issuer ||
		c.Audience != Audience || c.Subject != v.subject:
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

// parse checks token's structure and signature, and returns its claims and
// the issuer they must carry.
func (v *Verifier) parse(token string, now time.Time) (*Claims, string, error) {
	t, err := jws.Parse(token, maxTokenLen, tokenType, true)
	if err != nil {
		return nil, "", reject(err.Error())
	}
	key, issuer, err := v.signingKey(t.Header, now)
	if err != nil {
		return nil, "", err
	}
	var c Claims
	if err := t.Verify(key, &c, jws.IgnoreUnknown); err != nil {
		return nil, "", reject(err.Error())
	}
	if err := c.valid(); err != nil {
		return nil, "", err
	}
	return &c, issuer, nil
}

// signingKey is the key that must have signed a capability with h, and the
// issuer its claims must carry. With roots, an x5c chain decides: its
// certificate's key and issuer, and a kid naming a pinned key must name that
// same key, so a verifier with keys and one with roots never accept a token
// under two different keys. Without roots x5c is ignored, which keeps pinned
// keys working as a signer starts sending its certificate.
func (v *Verifier) signingKey(h jws.Header, now time.Time) (*ecdsa.PublicKey, string, error) {
	pinned := v.keys[h.Kid]
	switch {
	case h.X5C != nil && v.chains != nil:
		certs, err := parseChain(h.X5C)
		if err != nil {
			return nil, "", err
		}
		key, issuer, err := v.chains.verify(certs, now)
		if err != nil {
			return nil, "", err
		}
		if pinned != nil && !pinned.Equal(key) {
			return nil, "", reject("kid names a pinned key the x5c certificate does not certify")
		}
		return key, issuer, nil
	case pinned != nil:
		return pinned, v.issuer, nil
	case h.X5C != nil:
		return nil, "", reject("x5c, and this verifier trusts no roots")
	}
	return nil, "", reject("unknown kid")
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
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		key, ok := parsed.(*ecdsa.PublicKey)
		if block.Type != "PUBLIC KEY" || err != nil || !ok || key.Curve != elliptic.P256() ||
			kid == "" || keys[kid] != nil {
			return nil, fmt.Errorf("capability: key %q needs a unique Key-ID and a P-256 key", kid)
		}
		keys[kid] = key
	}
	if len(keys) == 0 {
		return nil, errors.New("capability: no keys")
	}
	return keys, nil
}
