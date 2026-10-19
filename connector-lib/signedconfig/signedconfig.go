// Package signedconfig signs and verifies OTA connector configs. A signed
// config is the config document with one line before it:
//
//	# traversal-signature: <ES256 compact JWS>
//
// TOML ignores comments, so connectors without config keys read the same
// object unchanged. The JWS payload binds the document (its SHA-256, over
// every byte after that line) to one connector, a version and a validity
// window, so a config cannot be moved to another connector, replayed over a
// newer one, or replayed at all once it expires: a connector that restarts
// has no applied config to compare with, so expiry is what bounds a replay
// then.
package signedconfig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/jws"
)

const (
	// Prefix starts a signed config's first line.
	Prefix = "# traversal-signature: "
	// tokenType is the JWS typ header, not a credential.
	tokenType = "traversal-config+jwt" //nolint:gosec // G101: a media type
	// Audience is the only audience a config signature carries, so a
	// capability (another typ and audience) never verifies as one.
	Audience    = "traversal-connector-config"
	maxTokenLen = 2048
	// MaxClockSkew is how far a connector's clock may be from the signer's:
	// a config is valid from iat - MaxClockSkew to exp + MaxClockSkew.
	MaxClockSkew = 5 * time.Minute
)

// Claims is a config signature's payload. Every field is required.
type Claims struct {
	Audience    string `json:"aud"`
	ConnectorID string `json:"connector_id"`
	// Version only goes up for one connector; the connector refuses a lower
	// one than it holds.
	Version uint64 `json:"version"`
	// SHA256 is the hex digest of the document after the signature line.
	SHA256 string `json:"sha256"`
	// IssuedAt and ExpiresAt, Unix seconds, bound when a connector accepts
	// the config. IssuedAt only goes up for one connector too: the connector
	// refuses one issued before the config it holds.
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

// Sign returns document signed for connector at version, by key under kid,
// valid from issued until expires.
func Sign(key *ecdsa.PrivateKey, kid, connector string, version uint64,
	issued, expires time.Time, document []byte,
) ([]byte, error) {
	switch {
	case kid == "" || connector == "" || version == 0:
		return nil, errors.New("signedconfig: kid, connector and version are required")
	case issued.Unix() <= 0 || !expires.After(issued):
		return nil, errors.New("signedconfig: expires must be after issued")
	}
	sum := sha256.Sum256(document)
	token, err := jws.Sign(key, jws.Header{Typ: tokenType, Kid: kid},
		Claims{Audience: Audience, ConnectorID: connector, Version: version,
			SHA256: hex.EncodeToString(sum[:]), IssuedAt: issued.Unix(),
			ExpiresAt: expires.Unix()})
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString(Prefix + token + "\n")
	out.Write(document)
	return out.Bytes(), nil
}

// Verify checks a signed config for connector against keys (by kid), valid
// at now, and returns the document and its claims. It never quotes the
// input.
func Verify(object []byte, connector string, keys map[string]*ecdsa.PublicKey, now time.Time,
) ([]byte, *Claims, error) {
	line, document, ok := bytes.Cut(object, []byte("\n"))
	token, signed := strings.CutPrefix(strings.TrimSuffix(string(line), "\r"), Prefix)
	if !ok || !signed {
		return nil, nil, errors.New("config is not signed")
	}
	// Decoded as capabilities are, strictly: no unknown, duplicate or
	// case-variant keys, no trailing data.
	t, err := jws.Parse(token, maxTokenLen, tokenType, false)
	switch {
	case errors.Is(err, jws.ErrMalformed):
		return nil, nil, errors.New("config signature is not a compact JWS")
	case err != nil:
		return nil, nil, errors.New("config signature has a bad header")
	}
	key, ok := keys[t.Header.Kid]
	if !ok {
		return nil, nil, errors.New("config is signed by an unknown key")
	}
	var c Claims
	switch err := t.Verify(key, &c, jws.RefuseUnknown); {
	case errors.Is(err, jws.ErrSignature):
		return nil, nil, errors.New("config signature does not verify")
	case err != nil:
		return nil, nil, errors.New("config signature has bad claims")
	}
	sum := sha256.Sum256(document)
	switch {
	case c.Audience != Audience:
		return nil, nil, errors.New("config signature is for another audience")
	case c.ConnectorID != connector:
		return nil, nil, errors.New("config is for another connector")
	case c.Version == 0:
		return nil, nil, errors.New("config signature has no version")
	case c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt:
		return nil, nil, errors.New("config signature has a bad validity window")
	case now.Add(MaxClockSkew).Before(time.Unix(c.IssuedAt, 0)):
		return nil, nil, errors.New("config signature is not valid yet")
	case !now.Add(-MaxClockSkew).Before(time.Unix(c.ExpiresAt, 0)):
		return nil, nil, errors.New("config signature has expired")
	case c.SHA256 != hex.EncodeToString(sum[:]):
		return nil, nil, errors.New("config does not match its signature")
	}
	return document, &c, nil
}
