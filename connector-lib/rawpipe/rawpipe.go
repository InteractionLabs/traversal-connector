// Package rawpipe is what the connector, the tunnel gateway and the
// Integration Proxy share about raw pipes: the tunnel protocol, headers, and
// why an open was refused.
package rawpipe

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
)

// Tunnel protocol. A connector dials the controller host with ALPN, writes
// Preface, a space, its connector ID and a newline, then serves HTTP/2: the
// gateway opens one CONNECT stream per pipe. A DrainMethod request asks the
// connector for a replacement tunnel.
const (
	ALPN        = "x-traversal-tunnel"
	Preface     = "TRAVERSAL-TUNNEL/1"
	DrainMethod = "TRAVERSAL-DRAIN"
)

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
