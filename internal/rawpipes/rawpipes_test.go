package rawpipes

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
)

const connector = "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d00"

// loopback dials every destination at addr, standing in for dialpolicy,
// which refuses loopback.
type loopback string

func (a loopback) Dial(
	ctx context.Context,
	_ string,
	_ uint16,
) (rawpipe.HalfCloser, string, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", string(a))
	if err != nil {
		return nil, "", rawpipe.Errorf(rawpipe.DialFailed, "%v", err)
	}
	return c.(*net.TCPConn), string(a), nil //nolint:forcetypeassert // tcp
}

// echo upper-cases what it reads until EOF, then closes.
func echo(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b, _ := io.ReadAll(c)
			_, _ = c.Write([]byte(strings.ToUpper(string(b))))
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

// gateway listens for a tunnel and points tunnels at itself. accept takes
// the tunnel, checks its preface, and returns an HTTP/2 client on it, as the
// tunnel gateway does.
func gateway(t *testing.T, tunnels *Tunnels) (accept func() *http2.ClientConn) {
	srv := httptest.NewTLSServer(nil)
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	ln, err := tls.Listen("tcp", "127.0.0.1:0",
		&tls.Config{Certificates: srv.TLS.Certificates, NextProtos: []string{rawpipe.ALPN}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tunnels.Addr = ln.Addr().String()
	tunnels.TLS = &tls.Config{
		RootCAs:    roots,
		ServerName: "example.com",
		NextProtos: []string{rawpipe.ALPN},
	}
	return func() *http2.ClientConn {
		c, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		br := bufio.NewReader(c)
		if line, err := br.ReadString('\n'); err != nil ||
			line != rawpipe.Preface+" "+connector+"\n" {
			t.Fatalf("preface %q: %v", line, err)
		}
		cc, err := (&http2.Transport{}).NewClientConn(c)
		if err != nil {
			t.Fatal(err)
		}
		return cc
	}
}

// open opens a pipe, sending body and then closing the caller's end once
// hold is closed. It returns the status, the refusal reason, and the
// destination's bytes.
func open(
	t *testing.T,
	cc *http2.ClientConn,
	token, body string,
	hold <-chan struct{},
) (int, string, io.ReadCloser) {
	pr, pw := io.Pipe()
	req, _ := http.NewRequest(http.MethodConnect, "https://db.internal:5432", pr)
	req.Host = "db.internal:5432"
	req.Header.Set(rawpipe.HeaderCapability, token)
	go func() {
		_, _ = pw.Write([]byte(body))
		if hold != nil {
			<-hold
		}
		_ = pw.Close()
	}()
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp.StatusCode, resp.Header.Get(rawpipe.HeaderReason), resp.Body
}

func read(r io.Reader) string { b, _ := io.ReadAll(r); return string(b) }

func TestPipes(t *testing.T) {
	key := capabilitytest.Key("rawpipes")
	verifier, err := capability.NewVerifier("traversal-raw-tunnel/test", "integration-proxy",
		map[string]*ecdsa.PublicKey{"k": &key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	tunnels := &Tunnels{ConnectorID: connector, Count: 1, Server: &Server{
		ConnectorID: connector, Verifier: verifier, Policy: loopback(echo(t)), MaxPipes: 4,
	}}
	accept := gateway(t, tunnels)
	ctx, cancel := context.WithCancel(t.Context())
	done := tunnels.Start(ctx)
	cc := accept()

	token := func() string {
		tok, err := capability.Sign(key, "k",
			capabilitytest.Claims("traversal-raw-tunnel/test", connector, "db.internal", 5432))
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	if status, _, body := open(t, cc, token(), "ping", nil); status != 200 || read(body) != "PING" {
		t.Fatalf("pipe: %d", status)
	}
	if status, reason, _ := open(t, cc, "bogus", "", nil); status != 401 ||
		reason != string(rawpipe.InvalidCapability) {
		t.Fatalf("bad capability: %d %s", status, reason)
	}
	if ok, _ := tunnels.Ready(ctx); !ok {
		t.Fatal("not ready with a tunnel up")
	}

	// A draining connector refuses new pipes and lets open ones finish.
	hold := make(chan struct{})
	_, _, held := open(t, cc, token(), "held", hold)
	cancel()
	for !tunnels.Server.draining.Load() {
		time.Sleep(time.Millisecond)
	}
	if status, reason, _ := open(t, cc, token(), "", nil); status != 503 ||
		reason != string(rawpipe.Draining) {
		t.Fatalf("draining: %d %s", status, reason)
	}
	close(hold)
	if got := read(held); got != "HELD" {
		t.Fatalf("held pipe: %q", got)
	}
	<-done
}
