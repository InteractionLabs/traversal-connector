// Package rawpipe is what the connector, the edge controller and the
// Integration Proxy share about raw pipes: the tunnel protocol, headers, and
// why an open was refused.
package rawpipe

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// Tunnel protocol. A connector dials the controller host with ALPN, writes
// its preface line (WritePreface), then serves HTTP/2: the edge controller
// opens one CONNECT stream per pipe. A DrainMethod request asks the
// connector for a replacement tunnel.
const (
	ALPN        = "x-traversal-tunnel"
	Preface     = "TRAVERSAL-TUNNEL/1"
	DrainMethod = "TRAVERSAL-DRAIN"
	// MaxPrefaceLen bounds a preface line, its newline included.
	MaxPrefaceLen = 512
)

// A preface line is Preface, a space, the connector ID, then optional
// space-separated key=value fields naming the capability trust the connector
// has loaded, each a comma-separated list:
//
//	TRAVERSAL-TUNNEL/1 <connector-id> roots=<fingerprint>,... kids=<kid>,...
//
// A field whose list is empty is left out.
const (
	prefaceRoots = "roots"
	prefaceKids  = "kids"
)

// RootFingerprint names a capability root in a preface: the first 16 hex
// digits of the SHA-256 of its DER.
func RootFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}

// WritePreface writes the preface line for connectorID, reporting roots
// (RootFingerprint each) and kids, the pinned keys' IDs. It refuses a line
// ParsePreface would not read back: a connector ID that is not a lower-case
// UUID, a value that is empty or holds a space, comma or control byte, or a
// line over MaxPrefaceLen.
func WritePreface(w io.Writer, connectorID string, roots, kids []string) error {
	if !IsConnectorID(connectorID) {
		return fmt.Errorf("rawpipe: preface: %q is not a connector ID", connectorID)
	}
	line := Preface + " " + connectorID
	for _, f := range []struct {
		key    string
		values []string
	}{{prefaceRoots, roots}, {prefaceKids, kids}} {
		if len(f.values) == 0 {
			continue
		}
		for _, v := range f.values {
			if !prefaceValue(v) {
				return fmt.Errorf("rawpipe: preface: %s value %q", f.key, v)
			}
		}
		line += " " + f.key + "=" + strings.Join(f.values, ",")
	}
	if line += "\n"; len(line) > MaxPrefaceLen {
		return fmt.Errorf("rawpipe: preface: %d bytes, over %d", len(line), MaxPrefaceLen)
	}
	_, err := io.WriteString(w, line)
	return err
}

// ParsePreface reads a preface line, with or without its newline. It is
// strict about the tag and the connector ID, and lenient about fields:
// unknown key=value fields are ignored, so a connector can report more
// without a controller release. A field that is not key=value, or a known
// key given twice, refuses the line.
func ParsePreface(line string) (connectorID string, roots, kids []string, ok bool) {
	fields := strings.Split(strings.TrimSuffix(line, "\n"), " ")
	if len(fields) < 2 || fields[0] != Preface || !IsConnectorID(fields[1]) {
		return "", nil, nil, false
	}
	seen := map[string]bool{}
	for _, f := range fields[2:] {
		key, value, isField := strings.Cut(f, "=")
		if !isField || key == "" || seen[key] {
			return "", nil, nil, false
		}
		seen[key] = true
		var list []string
		if value != "" {
			list = strings.Split(value, ",")
		}
		switch key {
		case prefaceRoots:
			roots = list
		case prefaceKids:
			kids = list
		}
	}
	return fields[1], roots, kids, true
}

// prefaceValue reports whether v can stand in a preface list: printable
// ASCII, neither a space nor a comma.
func prefaceValue(v string) bool {
	for i := range len(v) {
		if v[i] <= ' ' || v[i] > '~' || v[i] == ',' {
			return false
		}
	}
	return v != ""
}

// Reason says why an open was refused. It travels in HeaderReason.
type Reason string

// Refusal reasons.
const (
	InvalidCapability  Reason = "invalid_capability"
	WrongConnector     Reason = "wrong_connector"
	WrongDestination   Reason = "wrong_destination"
	Exhausted          Reason = "capability_exhausted"
	InspectionRequired Reason = "inspection_required"
	ForbiddenAddress   Reason = "forbidden_address"
	DNSFailed          Reason = "dns_failed"
	DialFailed         Reason = "dial_failed"
	Capacity           Reason = "capacity"
	Draining           Reason = "connector_draining"
	ProtocolError      Reason = "protocol_error"
	NoTunnel           Reason = "no_raw_tunnel"
	OpenTimeout        Reason = "open_timeout"
	// TCPRefused is a connector whose operator turned raw TCP pipes off.
	TCPRefused Reason = "raw_tcp_refused"
)

// Known reports whether r is one of the refusal reasons above. Metrics and
// the proxy name a known reason and report anything else as "other", which
// keeps label sets closed whatever a peer sends.
func (r Reason) Known() bool {
	switch r {
	case InvalidCapability, WrongConnector, WrongDestination, Exhausted, InspectionRequired,
		ForbiddenAddress, DNSFailed, DialFailed, Capacity, Draining, ProtocolError, NoTunnel,
		OpenTimeout, TCPRefused:
		return true
	}
	return false
}

// Headers on a CONNECT between Traversal and the connector.
const (
	HeaderCapability = "X-Capability"
	HeaderReason     = "X-Traversal-Reason"
	// HeaderNodeID names the connector a pipe is for: the controller picks
	// that connector's tunnel and verifies the capability against it.
	HeaderNodeID = "X-Node-Id"
)

// Error is a refused open.
type Error struct {
	Reason Reason
	msg    string
}

func (e *Error) Error() string { return string(e.Reason) + ": " + e.msg }

// Errorf returns an *Error for reason.
func Errorf(reason Reason, format string, args ...any) error {
	return &Error{Reason: reason, msg: fmt.Sprintf(format, args...)}
}

// ReasonOf is err's reason, or fallback if err is not an *Error.
func ReasonOf(err error, fallback Reason) Reason {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Reason
	}
	return fallback
}

// Status is the HTTP status that accompanies a refusal.
func (r Reason) Status() int {
	switch r {
	case InvalidCapability:
		return http.StatusUnauthorized
	case DNSFailed, DialFailed:
		return http.StatusBadGateway
	case Capacity, Draining, NoTunnel, OpenTimeout:
		return http.StatusServiceUnavailable
	case ProtocolError:
		return http.StatusBadRequest
	default:
		return http.StatusForbidden
	}
}

const uuid = `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`

var (
	canonicalUUID = regexp.MustCompile(`^` + uuid + `$`)
	tenantID      = regexp.MustCompile(
		`^spiffe://traversal\.com/tenant/(` + uuid + `)/[^/]+(?:/connector/(` + uuid + `))?$`,
	)
)

// IsConnectorID reports whether id is a lower-case UUID, the only form a
// tunnel may name.
func IsConnectorID(id string) bool { return canonicalUUID.MatchString(id) }

// TenantID parses a connector certificate's SPIFFE ID: org-scoped,
// spiffe://traversal.com/tenant/<org>/<name>, or connector-scoped, the same
// ending /connector/<connector>. connector is empty for an org-scoped ID.
func TenantID(uri string) (org, connector string, ok bool) {
	m := tenantID.FindStringSubmatch(uri)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}
