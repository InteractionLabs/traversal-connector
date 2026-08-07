package executor

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"

	"github.com/InteractionLabs/traversal-connector/connector-lib/connector"
)

// ErrorKind classifies a failure produced by Executor.Execute. The grpc
// handler maps each kind to a wire-level connector.ErrorCode so the
// controller can pick an appropriate HTTP status for the original caller.
type ErrorKind int

const (
	// KindInternal is a connector bug or unexpected error. HTTP 500.
	KindInternal ErrorKind = iota
	// KindInvalidRequest is a malformed caller request (bad URL, etc). HTTP 400.
	KindInvalidRequest
	// KindRequestTooLarge means the request body exceeded the configured
	// limit. HTTP 413.
	KindRequestTooLarge
	// KindUpstreamTimeout means our deadline fired waiting on the upstream.
	// HTTP 504. Note: an upstream that itself returns 504 is passed through
	// as a normal HttpResponse, not classified here.
	KindUpstreamTimeout
	// KindUpstreamUnavailable means we could not establish or complete a
	// connection to the upstream (DNS, dial, TLS). HTTP 502.
	KindUpstreamUnavailable
	// KindUpstreamAborted means the upstream accepted the request but closed
	// the connection mid-response. HTTP 502.
	KindUpstreamAborted
	// KindClientCanceled means the controller cancelled the request before
	// the upstream returned. HTTP 499.
	KindClientCanceled
)

// UpstreamError wraps a network/IO failure with a classification used by the
// gRPC handler. Use newUpstreamError to construct one; classifyNetwork is the
// helper that picks a Kind from a raw error returned by net/http.
type UpstreamError struct {
	Kind ErrorKind
	Err  error
}

func (e *UpstreamError) Error() string {
	if e == nil || e.Err == nil {
		return "upstream error"
	}
	return e.Err.Error()
}

func (e *UpstreamError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// newUpstreamError constructs an UpstreamError with an explicit Kind, used at
// failure sites where the kind is unambiguous (e.g. body size limit).
func newUpstreamError(kind ErrorKind, err error) *UpstreamError {
	return &UpstreamError{Kind: kind, Err: err}
}

// classifyNetwork inspects an error returned from http.Client.Do or
// io.ReadAll on a response body and returns the matching ErrorKind. Caller
// cancellation is reported separately from a hard timeout because the two
// have different semantics for the controller.
func classifyNetwork(err error) ErrorKind {
	if err == nil {
		return KindInternal
	}
	switch {
	case errors.Is(err, context.Canceled):
		return KindClientCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return KindUpstreamTimeout
	case errors.Is(err, io.ErrUnexpectedEOF),
		errors.Is(err, io.EOF),
		errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.EPIPE):
		return KindUpstreamAborted
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return KindUpstreamTimeout
	}
	// Anything else network-shaped (dial refused, DNS, TLS) — treat as the
	// upstream being unreachable rather than a bug in the connector.
	var oe *net.OpError
	if errors.As(err, &oe) {
		return KindUpstreamUnavailable
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return KindUpstreamUnavailable
	}
	return KindInternal
}

// ErrorCodeFor maps an ErrorKind to the wire-level connector.ErrorCode used
// in pb.ErrorResponse. Kept here so the mapping is colocated with the kind
// definitions and easy to keep in sync.
func ErrorCodeFor(k ErrorKind) connector.ErrorCode {
	switch k {
	case KindInvalidRequest:
		return connector.ErrorCodeInvalidRequest
	case KindRequestTooLarge:
		return connector.ErrorCodeRequestTooLarge
	case KindUpstreamTimeout:
		return connector.ErrorCodeUpstreamTimeout
	case KindUpstreamUnavailable:
		return connector.ErrorCodeUpstreamUnavailable
	case KindUpstreamAborted:
		return connector.ErrorCodeUpstreamAborted
	case KindClientCanceled:
		return connector.ErrorCodeClientCanceled
	default:
		return connector.ErrorCodeInternal
	}
}
