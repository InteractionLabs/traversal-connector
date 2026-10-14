// Package jws is the compact ES256 JWS every token connector-lib verifies
// shares: capabilities and signed configs. It parses strictly: the header
// holds exactly alg, typ, kid and, where allowed, x5c; no key may repeat,
// exactly or by case, at any depth of either segment; nothing may trail the
// JSON; and every claim the claims type names is required unless tagged
// omitempty. Signatures are golang-jwt's.
//
// testdata/vectors.json holds golden tokens and the verdict each must get,
// for this package's tests and for ports to other languages.
package jws

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Algorithm is the only alg a token may carry.
const Algorithm = "ES256"

// Why a token was refused. They never quote it.
var (
	ErrMalformed = errors.New("not a compact JWS")
	ErrHeader    = errors.New("bad header")
	ErrSignature = errors.New("bad signature")
	ErrClaims    = errors.New("bad claims")
)

// Header is a token's JWS header.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
	// X5C is the signing key's certificate chain (RFC 7515 section 4.1.6:
	// standard base64 DER, leaf first), where Parse allows it.
	X5C []string `json:"x5c,omitempty"`
}

var (
	chainedHeaderKeys = jsonKeys(reflect.TypeFor[Header]())
	plainHeaderKeys   = func() map[string]bool {
		keys := jsonKeys(reflect.TypeFor[Header]())
		delete(keys, "x5c")
		return keys
	}()
)

// Token is a parsed token whose signature is not yet checked: only Verify
// reaches its claims.
type Token struct {
	Header Header
	input  string // header.payload, what the signature covers
	sig    string
}

// Parse splits token, at most maxLen bytes, and decodes its header, which
// must name Algorithm and typ. chained allows x5c in the header.
func Parse(token string, maxLen int, typ string, chained bool) (*Token, error) {
	parts := strings.Split(token, ".")
	if len(token) > maxLen || len(parts) != 3 {
		return nil, ErrMalformed
	}
	known := plainHeaderKeys
	if chained {
		known = chainedHeaderKeys
	}
	t := &Token{input: parts[0] + "." + parts[1], sig: parts[2]}
	if err := decodeSegment(parts[0], known, RefuseUnknown, &t.Header); err != nil ||
		t.Header.Alg != Algorithm || t.Header.Typ != typ {
		return nil, ErrHeader
	}
	return t, nil
}

// Unknown says what Verify does with a claim the claims type does not name.
type Unknown bool

const (
	RefuseUnknown Unknown = false
	IgnoreUnknown Unknown = true
)

// Verify checks t's signature against key and only then decodes its claims
// into claims, a pointer to a struct.
func (t *Token) Verify(key *ecdsa.PublicKey, claims any, unknown Unknown) error {
	sig, err := base64.RawURLEncoding.DecodeString(t.sig)
	if err != nil || jwt.SigningMethodES256.Verify(t.input, sig, key) != nil {
		return ErrSignature
	}
	payload := t.input[strings.IndexByte(t.input, '.')+1:]
	known := jsonKeys(reflect.TypeOf(claims).Elem())
	if err := decodeSegment(payload, known, unknown, claims); err != nil {
		return ErrClaims
	}
	return nil
}

// Sign returns claims as a token with header h, signed by key. It sets
// h.Alg.
func Sign(key *ecdsa.PrivateKey, h Header, claims any) (string, error) {
	h.Alg = Algorithm
	hdr, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64(hdr) + "." + b64(p)
	sig, err := jwt.SigningMethodES256.Sign(input, key)
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// decodeSegment parses a JWS segment, a JSON object, into v. Every key in
// known marked required must be present and not null; a key not in known is
// refused unless unknown is IgnoreUnknown, even one v has a field for (x5c
// where a token may not carry it). encoding/json/v2 refuses a key
// repeated exactly at any depth, trailing data and invalid UTF-8, and
// matches keys exactly (v1 folds case, and "ſ" onto "s"); foldedUnique
// refuses what it allows, a key repeated by case.
func decodeSegment(segment string, known map[string]bool, unknown Unknown, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	var obj map[string]jsontext.Value
	if err := jsonv2.Unmarshal(raw, &obj); err != nil {
		return err
	}
	if err := foldedUnique(raw); err != nil {
		return err
	}
	for k, required := range known {
		if val, ok := obj[k]; required && (!ok || val.Kind() == 'n') {
			return fmt.Errorf("missing field %q", k)
		}
	}
	for k := range obj {
		if _, named := known[k]; !named && unknown == RefuseUnknown {
			return fmt.Errorf("unknown field %q", k)
		}
	}
	return jsonv2.Unmarshal(raw, v)
}

// foldedUnique refuses a JSON object, at any depth of raw, with two keys
// that differ only by case. jsontext has no option for this: it compares
// names exactly.
func foldedUnique(raw []byte) error {
	d := jsontext.NewDecoder(bytes.NewReader(raw))
	var seen []map[string]bool // one per open object
	for {
		tok, err := d.ReadToken()
		if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
		switch tok.Kind() {
		case '{':
			seen = append(seen, map[string]bool{})
		case '}':
			seen = seen[:len(seen)-1]
		case '"':
			// A string at an odd position in an object is a key.
			if kind, n := d.StackIndex(d.StackDepth()); kind == '{' && n%2 == 1 {
				key := strings.ToLower(tok.String())
				if seen[len(seen)-1][key] {
					return fmt.Errorf("duplicate key %q", key)
				}
				seen[len(seen)-1][key] = true
			}
		}
	}
}

// jsonKeys maps each JSON key of struct type t to whether it is required:
// every field but those tagged omitempty.
func jsonKeys(t reflect.Type) map[string]bool {
	keys := make(map[string]bool, t.NumField())
	for i := range t.NumField() {
		name, opts, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		keys[name] = opts != "omitempty"
	}
	return keys
}
