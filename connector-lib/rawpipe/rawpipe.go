// Package rawpipe is what the connector, the edge controller and the
// Integration Proxy share about raw pipes: the tunnel protocol, headers, and
// why an open was refused.
package rawpipe

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
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
// space-separated key=value fields:
//
//	TRAVERSAL-TUNNEL/1 <connector-id> roots=<fingerprint>,... kids=<kid>,...
//
// roots and kids name the capability trust the connector has loaded, each a
// comma-separated list; a field whose list is empty is left out.
const (
	prefaceRoots = "roots"
	prefaceKids  = "kids"
)

// Hello is what a preface line reports.
type Hello struct {
	ConnectorID string
	// Roots and Kids are the capability trust the connector has loaded: each
	// root's RootFingerprint, and the pinned keys' IDs.
	Roots, Kids []string
}

// RootFingerprint names a capability root in a preface: the first 16 hex
// digits of the SHA-256 of its DER.
func RootFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}

// WritePreface writes h's preface line. It refuses a line ParsePreface would
// not read back: a connector ID that is not a lower-case UUID, a root or kid
// that is empty or holds a space, comma or control byte, or a line over
// MaxPrefaceLen.
func WritePreface(w io.Writer, h Hello) error {
	if !IsConnectorID(h.ConnectorID) {
		return fmt.Errorf("rawpipe: preface: %q is not a connector ID", h.ConnectorID)
	}
	line := Preface + " " + h.ConnectorID
	for _, f := range []struct {
		key    string
		values []string
	}{{prefaceRoots, h.Roots}, {prefaceKids, h.Kids}} {
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
// strict about the tag, the connector ID and the fields it knows, and
// lenient about the rest: unknown key=value fields are ignored, so a
// connector can report more without a controller release. A field that is
// not key=value, or a known key given twice, refuses the line.
func ParsePreface(line string) (Hello, bool) {
	fields := strings.Split(strings.TrimSuffix(line, "\n"), " ")
	if len(fields) < 2 || fields[0] != Preface || !IsConnectorID(fields[1]) {
		return Hello{}, false
	}
	h := Hello{ConnectorID: fields[1]}
	seen := map[string]bool{}
	for _, f := range fields[2:] {
		key, value, isField := strings.Cut(f, "=")
		if !isField || key == "" || seen[key] {
			return Hello{}, false
		}
		seen[key] = true
		var list []string
		if value != "" {
			list = strings.Split(value, ",")
		}
		switch key {
		case prefaceRoots:
			h.Roots = list
		case prefaceKids:
			h.Kids = list
		}
	}
	return h, true
}

// ErrPreface is a preface line ReadPreface refused: over MaxPrefaceLen, or
// one ParsePreface does not read. Its other errors are the reader's.
var ErrPreface = errors.New("rawpipe: bad preface")

// ReadPreface reads a preface line from r a byte at a time, so a peer that
// sends more than MaxPrefaceLen bytes, its newline included, is refused before
// the line is buffered, and leaves what follows it in r.
func ReadPreface(r *bufio.Reader) (Hello, error) {
	var line []byte
	for len(line) < MaxPrefaceLen {
		b, err := r.ReadByte()
		if err != nil {
			return Hello{}, err
		}
		if line = append(line, b); b == '\n' {
			h, ok := ParsePreface(string(line))
			if !ok {
				return Hello{}, fmt.Errorf("%w: %q", ErrPreface, line)
			}
			return h, nil
		}
	}
	return Hello{}, fmt.Errorf("%w: longer than %d bytes", ErrPreface, MaxPrefaceLen)
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
	// RedactionUnsupported is a request to a host redaction rules cover
	// whose body cannot be redacted: gRPC, binary, an upgrade, a stream with
	// no end, or one over the limits. It is refused, never sent unredacted.
	RedactionUnsupported Reason = "redaction_unsupported"
	// UpstreamFailed is a request the destination did not answer: a TLS
	// failure, a reset or a timeout.
	UpstreamFailed Reason = "upstream_failed"
	// Other stands for any reason that is not Known.
	Other Reason = "other"
)

// Known reports whether r is one of the refusal reasons above, Other aside.
// Metrics and the proxy name a known reason and report anything else as
// Other, which keeps label sets closed whatever a peer sends.
func (r Reason) Known() bool {
	switch r {
	case InvalidCapability, WrongConnector, WrongDestination, Exhausted, InspectionRequired,
		ForbiddenAddress, DNSFailed, DialFailed, Capacity, Draining, ProtocolError, NoTunnel,
		OpenTimeout, TCPRefused, RedactionUnsupported, UpstreamFailed:
		return true
	}
	return false
}

// Label is r for a known reason, else Other: the value metrics and the proxy
// report, so a peer's answer never widens a closed set.
func (r Reason) Label() Reason {
	if r.Known() {
		return r
	}
	return Other
}

// Headers on a CONNECT between Traversal and the connector.
const (
	HeaderCapability = "X-Capability"
	HeaderReason     = "X-Traversal-Reason"
)

// HeaderUpstreamScheme is the scheme, http or https, of an HTTP/2 request the
// Integration Proxy sends inside a pipe. HTTP/2's :scheme is not visible to a
// net/http handler, and the pipe's own TLS says nothing about the
// destination's, so the proxy sets this on every HTTP/2 request; the
// connector treats it as https when absent and does not forward it.
const HeaderUpstreamScheme = "X-Traversal-Upstream-Scheme"

// HeaderPeerURISAN is the URI SAN of the connector certificate the edge
// gateway verified (Envoy's %DOWNSTREAM_PEER_URI_SAN%), on the CONNECT stream
// that carries a tunnel from the gateway to the edge controller.
const HeaderPeerURISAN = "X-Traversal-Peer-Uri-San"

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
	case DNSFailed, DialFailed, RedactionUnsupported, UpstreamFailed:
		return http.StatusBadGateway
	case Capacity, Draining, NoTunnel, OpenTimeout:
		return http.StatusServiceUnavailable
	case ProtocolError:
		return http.StatusBadRequest
	default:
		return http.StatusForbidden
	}
}

// IsConnectorID reports whether id is a UUID in canonical form (lower case,
// hyphenated), the only form a tunnel may name: two spellings of one ID would
// be two tunnel keys.
func IsConnectorID(id string) bool {
	u, err := uuid.Parse(id)
	return err == nil && u.String() == id
}

// TenantID parses a connector certificate's SPIFFE ID: org-scoped,
// spiffe://traversal.com/tenant/<org>/<name>, or connector-scoped, the same
// ending /connector/<connector>. connector is empty for an org-scoped ID.
func TenantID(uri string) (org, connector string, ok bool) {
	rest, ok := strings.CutPrefix(uri, "spiffe://traversal.com/tenant/")
	if !ok {
		return "", "", false
	}
	parts := strings.Split(rest, "/")
	switch {
	case len(parts) == 2 && parts[1] != "":
	case len(parts) == 4 && parts[1] != "" && parts[2] == "connector" && IsConnectorID(parts[3]):
		connector = parts[3]
	default:
		return "", "", false
	}
	if !IsConnectorID(parts[0]) {
		return "", "", false
	}
	return parts[0], connector, true
}

// CheckIdentity reports whether a connector certificate whose URI SAN is
// uriSAN may hold tunnels for connectorID: the SAN is a tenant SPIFFE ID
// (TenantID), and a connector-scoped one names connectorID.
func CheckIdentity(uriSAN, connectorID string) error {
	if !IsConnectorID(connectorID) {
		return fmt.Errorf("rawpipe: %q is not a connector ID", connectorID)
	}
	_, scoped, ok := TenantID(uriSAN)
	switch {
	case !ok:
		return fmt.Errorf("rawpipe: %q is not a tenant SPIFFE ID", uriSAN)
	case scoped != "" && scoped != connectorID:
		return fmt.Errorf("rawpipe: the identity is for connector %s, not %s", scoped, connectorID)
	}
	return nil
}
