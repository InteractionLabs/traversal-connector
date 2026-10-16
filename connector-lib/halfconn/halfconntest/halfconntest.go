// Package halfconntest makes connections that can half-close, for tests.
package halfconntest

import (
	"net"
	"testing"
)

// TCPPair is two ends of a loopback TCP connection, closed when the test
// ends. Each is a halfconn.Conn; net.Pipe is not, as it cannot CloseWrite.
func TCPPair(tb testing.TB) (a, b *net.TCPConn) {
	tb.Helper()
	ln, err := (&net.ListenConfig{}).Listen(tb.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	near, err := (&net.Dialer{}).DialContext(tb.Context(), "tcp", ln.Addr().String())
	if err != nil {
		tb.Fatal(err)
	}
	far, err := ln.Accept()
	if err != nil {
		_ = near.Close()
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = near.Close(); _ = far.Close() })
	//nolint:errcheck,forcetypeassert // tcp listeners and dials give *net.TCPConn
	return near.(*net.TCPConn), far.(*net.TCPConn)
}
