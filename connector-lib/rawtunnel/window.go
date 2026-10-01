package rawtunnel

import (
	"math"
	"net/http"
	"time"
)

const (
	// ProtocolVersion is the raw tunnel protocol version this package speaks.
	ProtocolVersion = 1
	// StreamWindow is the inner HTTP/2 receive window for one pipe. One
	// stalled pipe can hold at most this much unread data.
	StreamWindow = 256 << 10
	// TunnelWindow is the receive window of the outer gRPC stream. Bytes sit
	// here until the inner session reads them, so this caps how much is in
	// flight for every pipe together. The inner connection window is separate.
	TunnelWindow = 1 << 20
	// maxChunk is the largest outer gRPC message. The adapter holds at most
	// one of these between Receive and the inner read that consumes it.
	maxChunk = 16 << 10
	// maxRecord is the largest length-prefixed record on a pipe body.
	maxRecord = 16 << 10

	// DefaultIdleTimeout ends a pipe on which no bytes moved in either
	// direction for this long.
	DefaultIdleTimeout = 15 * time.Minute
	// DefaultMaxLifetime ends a pipe this long after it opened.
	DefaultMaxLifetime = 4 * time.Hour
	// DefaultPingInterval is how often an idle inner session sends an HTTP/2 ping.
	DefaultPingInterval = 30 * time.Second
	// DefaultPingTimeout is how long a ping may go unanswered before the
	// session ends. The peer's HTTP/2 stack answers the ping, so a pipe that
	// has filled its stream window does not look dead.
	DefaultPingTimeout = 10 * time.Second
	// DefaultWriteByteTimeout is how long an outer HTTP/2 connection write may
	// make no progress before that connection is closed. It is not applied to
	// the inner session: a blocked inner write is flow control, not a dead TCP
	// connection.
	DefaultWriteByteTimeout = 30 * time.Second
)

// ConnectionWindow is the inner HTTP/2 connection window for a session that
// admits maxPipes pipes. Each pipe may park StreamWindow unread bytes, so the
// connection window is that sum: one unread pipe cannot stop the others.
//
// The window is advertised when the connection starts, from this side's cap.
// Hello may lower the pipe count afterward. HTTP/2 cannot shrink a window,
// and the pipes that are not opened simply leave the extra allowance unused.
func ConnectionWindow(maxPipes int) int {
	if maxPipes < 1 {
		maxPipes = 1
	}
	maxWindow := math.MaxInt32
	if maxPipes > maxWindow/StreamWindow {
		return maxWindow
	}
	return maxPipes * StreamWindow
}

// ApplyOuterWindows sets the gRPC connection's receive windows to exactly one
// outer window. The raw-tunnel client must call it: the HTTP/2 client default
// is much larger, and bytes the application has not Recv'd stay in that window.
func ApplyOuterWindows(cfg *http.HTTP2Config) {
	cfg.MaxReceiveBufferPerStream = TunnelWindow
	cfg.MaxReceiveBufferPerConnection = TunnelWindow
}
