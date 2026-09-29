package dialpolicy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

func TestForbidden(t *testing.T) {
	p, err := New(Config{Forbidden: []netip.Prefix{netip.MustParsePrefix("10.96.0.1/12")}})
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{
		"0.0.0.0", "0.1.2.3", "127.0.0.1", "127.255.255.254", "169.254.169.254",
		"169.254.170.2", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
		"100.100.100.200", "168.63.129.16", "192.0.0.192", "10.96.0.1", "10.111.255.255",
		"::", "::1", "::a9fe:a9fe", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "fe80::1",
		"fe80::1%eth0", "ff02::1", "fd00:ec2::254", "64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1",
	} {
		if !p.forbidden(netip.MustParseAddr(addr)) {
			t.Errorf("%s is allowed", addr)
		}
	}
	for _, addr := range []string{
		"10.0.0.1", "10.112.0.1", "172.16.0.1", "192.168.1.1", "8.8.8.8", "100.100.100.201",
		"169.253.255.255", "2001:db8::1", "fd00:ec2::253", "64:ff9b::a00:1",
	} {
		if p.forbidden(netip.MustParseAddr(addr)) {
			t.Errorf("%s is forbidden", addr)
		}
	}
	self, err := interfacePrefixes()
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range self {
		if !p.forbidden(prefix.Addr()) {
			t.Errorf("own address %s is allowed", prefix.Addr())
		}
	}
}

func TestNewRejectsInvalidPrefix(t *testing.T) {
	for _, prefix := range []netip.Prefix{
		{},
		netip.MustParsePrefix("::ffff:10.0.0.0/64"),
	} {
		if _, err := New(Config{Forbidden: []netip.Prefix{prefix}}); err == nil {
			t.Fatalf("New accepted %v", prefix)
		}
	}
}

func TestMappedForbiddenPrefixCoversIPv4(t *testing.T) {
	p, err := New(Config{
		Forbidden: []netip.Prefix{netip.MustParsePrefix("::ffff:10.96.0.0/108")},
		Proxy:     direct,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p.forbidden(netip.MustParseAddr("10.96.0.1")) ||
		!p.forbidden(netip.MustParseAddr("::ffff:10.96.0.1")) {
		t.Fatal("mapped prefix did not cover its IPv4 range")
	}
	if p.forbidden(netip.MustParseAddr("11.96.0.1")) {
		t.Fatal("mapped prefix covered an address outside it")
	}
}

// fakeNet resolves and dials test destinations: resolving hosts to addrs,
// and dialing those addresses by redirecting to real loopback listeners.
type fakeNet struct {
	t      *testing.T
	addrs  map[string][]string
	listen map[string]string

	mu      sync.Mutex
	lookups []string
	dials   []string
}

func (f *fakeNet) lookup(_ context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if network != "ip" {
		f.t.Errorf("lookup network = %q", network)
	}
	if _, err := netip.ParseAddr(host); err != nil && !strings.HasSuffix(host, ".") {
		f.t.Errorf("lookup %q is relative", host)
	}
	f.lookups = append(f.lookups, host)
	addrs, ok := f.addrs[strings.TrimSuffix(host, ".")]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []netip.Addr
	for _, a := range addrs {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

func (f *fakeNet) dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, address)
	real, ok := f.listen[address]
	f.mu.Unlock()
	if !ok {
		return nil, errors.New("unreachable")
	}
	var d net.Dialer
	return d.DialContext(ctx, network, real)
}

func (f *fakeNet) counts() (lookups, dials int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.lookups), len(f.dials)
}

func direct(string, uint16) (*url.URL, error) { return nil, nil }

func newPolicy(t *testing.T, f *fakeNet, cfg Config) *Policy {
	t.Helper()
	cfg.LookupNetIP, cfg.DialContext = f.lookup, f.dial
	if cfg.Proxy == nil {
		cfg.Proxy = direct
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// echoServer returns the address of a loopback server that echoes each
// connection and half-closes after the client does.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_, _ = io.Copy(c, c)
				_ = c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	return ln.Addr().String()
}

// roundTrip writes msg, half-closes, and expects msg echoed back then EOF.
func roundTrip(t *testing.T, c Conn, msg string) {
	t.Helper()
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || string(got) != msg {
		t.Fatalf("read %q, %v; want %q", got, err, msg)
	}
}

func wantCode(t *testing.T, err error, code Code) *Refusal {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) || r.Code != code {
		t.Fatalf("err = %v, want refusal %s", err, code)
	}
	return r
}

func TestDialDirect(t *testing.T) {
	echo := echoServer(t)
	f := &fakeNet{t: t,
		addrs:  map[string][]string{"db.internal": {"192.0.2.10"}},
		listen: map[string]string{"192.0.2.10:5432": echo, "[2001:db8::1]:5432": echo},
	}
	p := newPolicy(t, f, Config{})

	c, route, err := p.Dial(context.Background(), "db.internal", 5432)
	if err != nil {
		t.Fatal(err)
	}
	if route.Addr != netip.MustParseAddrPort("192.0.2.10:5432") || route.Proxy != nil {
		t.Fatalf("route = %+v", route)
	}
	roundTrip(t, c, "hello")

	c, route, err = p.Dial(context.Background(), "2001:db8::1", 5432)
	if err != nil {
		t.Fatal(err)
	}
	if route.Addr != netip.MustParseAddrPort("[2001:db8::1]:5432") {
		t.Fatalf("route = %+v", route)
	}
	roundTrip(t, c, "literal")
	if lookups, _ := f.counts(); lookups != 1 {
		t.Fatalf("%d lookups, want 1: literals are not resolved", lookups)
	}
}

func TestDialFallsBackToNextCheckedAddress(t *testing.T) {
	echo := echoServer(t)
	f := &fakeNet{t: t,
		addrs:  map[string][]string{"db.internal": {"192.0.2.10", "::ffff:192.0.2.11"}},
		listen: map[string]string{"192.0.2.11:5432": echo},
	}
	c, route, err := newPolicy(t, f, Config{}).Dial(context.Background(), "db.internal", 5432)
	if err != nil {
		t.Fatal(err)
	}
	if route.Addr != netip.MustParseAddrPort("192.0.2.11:5432") {
		t.Fatalf("route = %+v", route)
	}
	roundTrip(t, c, "hello")
	if f.dials[0] != "192.0.2.10:5432" || len(f.dials) != 2 {
		t.Fatalf("dials = %v", f.dials)
	}
}

func TestDialRefusals(t *testing.T) {
	inspected := func(host string, _ uint16) bool { return host == "pci.internal" }
	for _, tc := range []struct {
		name      string
		host      string
		port      uint16
		addrs     []string
		code      Code
		wantProbe bool
	}{
		{"uppercase", "DB.internal", 5432, nil, CodeInvalidDestination, false},
		{"trailing dot", "db.internal.", 5432, nil, CodeInvalidDestination, false},
		{"numeric name", "127.1", 5432, nil, CodeInvalidDestination, false},
		{"bracketed literal", "[::1]", 5432, nil, CodeInvalidDestination, false},
		{"empty host", "", 5432, nil, CodeInvalidDestination, false},
		{"zero port", "db.internal", 0, nil, CodeInvalidDestination, false},
		{"inspection", "pci.internal", 5432, []string{"192.0.2.10"}, CodeInspectionRequired, false},
		{"forbidden literal", "169.254.169.254", 80, nil, CodeForbiddenAddress, false},
		{"localhost", "localhost", 80, []string{"192.0.2.10"}, CodeForbiddenAddress, false},
		{"metadata name", "metadata.google.internal", 80, []string{"192.0.2.10"},
			CodeForbiddenAddress, false},
		{"one forbidden answer", "db.internal", 5432, []string{"192.0.2.10", "169.254.169.254"},
			CodeForbiddenAddress, true},
		{"mapped loopback answer", "db.internal", 5432, []string{"::ffff:127.0.0.1"},
			CodeForbiddenAddress, true},
		{"nat64 metadata answer", "db.internal", 5432, []string{"64:ff9b::a9fe:a9fe"},
			CodeForbiddenAddress, true},
		{"unresolvable", "missing.internal", 5432, nil, CodeResolveFailed, true},
		{"no answers", "db.internal", 5432, []string{}, CodeResolveFailed, true},
		{"unreachable", "db.internal", 5432, []string{"192.0.2.10"}, CodeDialFailed, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeNet{t: t, addrs: map[string][]string{}}
			if tc.addrs != nil {
				f.addrs[tc.host] = tc.addrs
			}
			p := newPolicy(t, f, Config{RequiresInspection: inspected})
			_, _, err := p.Dial(context.Background(), tc.host, tc.port)
			wantCode(t, err, tc.code)
			lookups, dials := f.counts()
			if probed := lookups > 0; probed != tc.wantProbe {
				t.Fatalf("%d lookups; want lookup %v", lookups, tc.wantProbe)
			}
			if tc.code != CodeDialFailed && dials > 0 {
				t.Fatalf("dialed %v after refusing", f.dials)
			}
		})
	}
}

func TestRefusalOpenFailureReasons(t *testing.T) {
	for code, want := range map[Code]pb.RawOpenFailureReason{
		CodeInvalidDestination:   pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_PROTOCOL_ERROR,
		CodeInspectionRequired:   pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_INSPECTION_REQUIRED,
		CodeForbiddenAddress:     pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_FORBIDDEN_ADDRESS,
		CodeProxyChecksDelegated: pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_FORBIDDEN_ADDRESS,
		CodeResolveFailed:        pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DNS_FAILED,
		CodeDialFailed:           pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_DIAL_FAILED,
	} {
		if got := refuse(code, nil).OpenFailureReason(); got != want {
			t.Errorf("%s maps to %v, want %v", code, got, want)
		}
	}
}
