package dialpolicy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"testing"

	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
)

type resolver map[string][]netip.Addr

func (r resolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func listen(t *testing.T) (*net.TCPListener, uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.(*net.TCPListener), uint16(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // a port
}

func reason(err error) rawpipe.Reason { return rawpipe.ReasonOf(err, "") }

func TestDial(t *testing.T) {
	_, port := listen(t)
	p := &Policy{cfg: Config{Resolver: resolver{
		"up.test.":       {netip.MustParseAddr("127.0.0.1")},
		"metadata.test.": {netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("169.254.169.254")},
		"nat64.test.":    {netip.MustParseAddr("64:ff9b::7f00:1")},
	}, RequiresInspection: func(h string) bool { return h == "redacted.test" }},
		deny: forbiddenPrefixes}
	for host, want := range map[string]rawpipe.Reason{
		"127.0.0.1":     rawpipe.ForbiddenAddress,
		"localhost":     rawpipe.ForbiddenAddress,
		"metadata.test": rawpipe.ForbiddenAddress, // one bad answer refuses the name
		"nat64.test":    rawpipe.ForbiddenAddress,
		"redacted.test": rawpipe.InspectionRequired,
		"missing.test":  rawpipe.DNSFailed,
		"up.test":       rawpipe.ForbiddenAddress,
	} {
		if _, _, err := p.Dial(context.Background(), host, port); reason(err) != want {
			t.Errorf("%s: %v, want %s", host, err, want)
		}
	}
	p.deny = nil
	conn, addr, err := p.Dial(context.Background(), "up.test", port)
	if err != nil || addr != netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String() {
		t.Fatalf("dial: %v %s", err, addr)
	}
	_ = conn.Close()
}

func TestDialThroughProxy(t *testing.T) {
	ln, port := listen(t)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil || req.Method != http.MethodConnect || req.Host != "db.internal.:5432" ||
			req.Header.Get("Proxy-Authorization") != "Basic dTpw" {
			_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\n\r\n")
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\nhello")
	}()
	proxy := &url.URL{Scheme: "http", User: url.UserPassword("u", "p"),
		Host: net.JoinHostPort("127.0.0.1", itoa(port))}
	strict, _ := New(Config{Proxy: proxy})
	if _, _, err := strict.Dial(context.Background(), "db.internal", 5432); reason(
		err,
	) != rawpipe.ForbiddenAddress {
		t.Fatalf("hostname without ProxyResolves: %v", err)
	}
	p, _ := New(Config{Proxy: proxy, ProxyResolves: true})
	conn, _, err := p.Dial(context.Background(), "db.internal", 5432)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if b, _ := io.ReadAll(conn); string(b) != "hello" {
		t.Fatalf("read %q through the tunnel", b)
	}
}

func itoa(p uint16) string { return strconv.Itoa(int(p)) }
