package upstream

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

// capStream bounds resp, a response from a host no rule covers, to
// streamCap when it is long-lived (an upgraded connection, an event stream
// or gRPC) and any rules exist. Coverage is decided when a request is sent,
// so a rule added later for the host reaches such a stream only once it ends
// and its client reopens it. Other responses, and every response while no
// rules exist, are untouched.
func (c *Client) capStream(resp *http.Response) {
	if c.streamCap <= 0 || !c.redactor.HasRules() {
		return
	}
	mediaType := mediaTypeOf(resp.Header.Get(headerContentType))
	switch {
	case resp.StatusCode == http.StatusSwitchingProtocols:
		// ReverseProxy splices an upgrade through the body as an
		// io.ReadWriteCloser; closing it ends both directions.
		if rwc, ok := resp.Body.(io.ReadWriteCloser); ok {
			capped := &cappedConn{ReadWriteCloser: rwc}
			capped.timer = time.AfterFunc(c.streamCap, func() { _ = rwc.Close() })
			resp.Body = capped
		}
	case mediaType == "text/event-stream" || isGRPC(mediaType):
		capped := &cappedBody{ReadCloser: resp.Body, resp: resp, grpc: isGRPC(mediaType)}
		capped.timer = time.AfterFunc(c.streamCap, func() {
			capped.expired.Store(true)
			_ = capped.ReadCloser.Close()
		})
		resp.Body = capped
	}
}

// grpcUnavailable is gRPC's UNAVAILABLE status: a client retries or
// reconnects, as it would after a server restart.
const grpcUnavailable = 14

// cappedBody ends a streamed response cleanly once its cap expires: the read
// the close interrupts is the end of the body, and a gRPC response gets
// UNAVAILABLE trailers, so its client reopens the stream.
type cappedBody struct {
	io.ReadCloser
	resp    *http.Response
	grpc    bool
	timer   *time.Timer
	expired atomic.Bool
}

func (b *cappedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == nil || errors.Is(err, io.EOF) || !b.expired.Load() {
		return n, err
	}
	if b.grpc {
		// ReverseProxy reads Trailer once the body has ended.
		if b.resp.Trailer == nil {
			b.resp.Trailer = make(http.Header)
		}
		b.resp.Trailer.Set("Grpc-Status", strconv.Itoa(grpcUnavailable))
		b.resp.Trailer.Set("Grpc-Message",
			"stream reached TRAVERSAL_UNCOVERED_STREAM_MAX_LIFETIME; reconnect")
	}
	return n, io.EOF
}

func (b *cappedBody) Close() error {
	b.timer.Stop()
	return b.ReadCloser.Close()
}

// cappedConn is an upgraded connection closed when its cap expires.
type cappedConn struct {
	io.ReadWriteCloser
	timer *time.Timer
}

func (c *cappedConn) Close() error {
	c.timer.Stop()
	return c.ReadWriteCloser.Close()
}
