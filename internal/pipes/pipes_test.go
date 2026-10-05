package pipes

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
	"github.com/InteractionLabs/traversal-connector/connector-lib/dialpolicy"
)

const (
	testConnector = "11111111-2222-4333-8444-555555555555"
	testIssuer    = "traversal-raw-tunnel/test"
	testKID       = "test-current"
	testSubject   = "integration-proxy"
	// publicAddr is what test destinations resolve to. The policy checks it;
	// the test dialer then connects to the local destination instead.
	publicAddr = "198.51.100.7"
)

var testKey = capabilitytest.Key("traversal-connector pipes test key")

// harness runs a Server on loopback with a destination listener the dial
// policy reaches whatever address it checked.
type harness struct {
	t        *testing.T
	server   *Server
	addr     string
	dest     net.Listener
	client   *http.Client
	resolved map[string]string // host → address the fake resolver returns
}

type harnessConfig struct {
	maxPipes    int64
	inspect     func(string, uint16) bool
	maxLifetime time.Duration
}

func newHarness(t *testing.T, hc harnessConfig) *harness {
	t.Helper()
	if hc.maxPipes == 0 {
		hc.maxPipes = 16
	}
	verifier, err := capability.NewVerifier(capability.VerifierConfig{
		Issuer:             testIssuer,
		Keys:               map[string]*ecdsa.PublicKey{testKID: &testKey.PublicKey},
		AllowedSubjects:    []string{testSubject},
		AllowUnknownClaims: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	dest, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dest.Close() })
	h := &harness{t: t, dest: dest, resolved: map[string]string{}}
	policy, err := dialpolicy.New(dialpolicy.Config{
		RequiresInspection: hc.inspect,
		Proxy:              func(string, uint16) (*url.URL, error) { return nil, nil },
		LookupNetIP: func(_ context.Context, _, host string) ([]netip.Addr, error) {
			addr, ok := h.resolved[strings.TrimSuffix(host, ".")]
			if !ok {
				addr = publicAddr
			}
			return []netip.Addr{netip.MustParseAddr(addr)}, nil
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, dest.Addr().String())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.server, err = New(Config{
		ConnectorID: testConnector,
		Verifier:    verifier,
		Policy:      policy,
		MaxPipes:    hc.maxPipes,
		MaxLifetime: hc.maxLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = h.server.Serve(ctx, ln) }()
	h.addr = ln.Addr().String()
	h.client = &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, h.addr)
		},
	}}
	return h
}

// capabilityFor signs a capability for host:port on this connector.
func capabilityFor(
	t *testing.T,
	host string,
	port uint16,
	mutate ...func(*capability.Claims),
) string {
	t.Helper()
	now := time.Now()
	claims := capability.Claims{
		Issuer:         testIssuer,
		Audience:       capability.Audience,
		Subject:        testSubject,
		OrganizationID: "org-1",
		IntegrationID:  "integration-1",
		ConnectorID:    testConnector,
		Host:           host,
		Port:           port,
		Mode:           capability.ModePassthrough,
		ConsumerID:     "test",
		TrafficClass:   "standard",
		SessionID:      "session-1",
		JTI:            now.Format(time.RFC3339Nano) + host,
		IssuedAt:       now.Unix(),
		ExpiresAt:      now.Add(2 * time.Minute).Unix(),
	}
	for _, m := range mutate {
		m(&claims)
	}
	token, err := capabilitytest.Sign(testKey, testKID, claims)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// pipe is an open CONNECT stream as a caller sees it.
type pipe struct {
	resp *http.Response
	body *io.PipeWriter
}

// connect opens a CONNECT to authority. It returns the response even when
// the open is refused.
func (h *harness) connect(authority, token string) (*pipe, error) {
	body, bodyWriter := io.Pipe()
	req, err := http.NewRequest(http.MethodConnect, "http://"+authority, body)
	if err != nil {
		return nil, err
	}
	req.Host = authority
	if token != "" {
		req.Header.Set(HeaderCapability, token)
	}
	resp, err := h.client.Transport.RoundTrip(req) //nolint:bodyclose // returned to the caller
	if err != nil {
		_ = bodyWriter.Close()
		return nil, err
	}
	return &pipe{resp: resp, body: bodyWriter}, nil
}

func (h *harness) open(host string, port uint16) *pipe {
	h.t.Helper()
	authority := capability.CanonicalAuthority(host, port)
	p, err := h.connect(authority, capabilityFor(h.t, host, port))
	if err != nil {
		h.t.Fatal(err)
	}
	if p.resp.StatusCode != http.StatusOK {
		h.t.Fatalf("open %s: %d %s", authority, p.resp.StatusCode, p.resp.Header.Get(HeaderReason))
	}
	return p
}

// accept returns the next connection the destination receives.
func (h *harness) accept() *net.TCPConn {
	h.t.Helper()
	conn, err := h.dest.Accept()
	if err != nil {
		h.t.Fatal(err)
	}
	return conn.(*net.TCPConn)
}

func TestHalfCloseBothWays(t *testing.T) {
	h := newHarness(t, harnessConfig{})
	p := h.open("db.internal", 5432)
	dst := h.accept()
	defer func() { _ = dst.Close() }()

	if _, err := p.body.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = p.body.Close() // END_STREAM: the destination sees FIN.
	got, err := io.ReadAll(dst)
	if err != nil || string(got) != "hello" {
		t.Fatalf("destination read %q, %v", got, err)
	}
	// The destination can still answer after the caller's FIN.
	if _, err := dst.Write([]byte("bye")); err != nil {
		t.Fatal(err)
	}
	_ = dst.CloseWrite()
	reply, err := io.ReadAll(p.resp.Body)
	if err != nil || string(reply) != "bye" {
		t.Fatalf("caller read %q, %v", reply, err)
	}
}

// The destination writes and closes while the caller is still sending. Every
// byte must arrive, then a clean end: this is what Go's own HTTP/2 server and
// Envoy's TCP upstream lose.
func TestDestinationClosesFirst(t *testing.T) {
	h := newHarness(t, harnessConfig{})
	p := h.open("db.internal", 5432)
	dst := h.accept()
	defer func() { _ = dst.Close() }()

	payload := bytes.Repeat([]byte("0123456789abcdef"), 4<<16) // 4 MiB
	go func() {
		_, _ = dst.Write(payload)
		_ = dst.CloseWrite()
	}()
	got, err := io.ReadAll(p.resp.Body)
	if err != nil {
		t.Fatalf("caller read %d bytes then %v", len(got), err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("caller read %d bytes, want %d", len(got), len(payload))
	}
	// Like TCP, the caller may keep sending after the destination's FIN.
	if _, err := p.body.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	_ = p.body.Close()
	late, err := io.ReadAll(dst)
	if err != nil || string(late) != "late" {
		t.Fatalf("destination read %q, %v", late, err)
	}
}

func TestDestinationResetReachesCaller(t *testing.T) {
	h := newHarness(t, harnessConfig{})
	p := h.open("db.internal", 5432)
	dst := h.accept()
	_, _ = dst.Write([]byte("partial"))
	_ = dst.SetLinger(0)
	_ = dst.Close()
	got, err := io.ReadAll(p.resp.Body)
	if err == nil {
		t.Fatalf("caller saw a clean end after %q; a reset must not look like a close", got)
	}
}

func TestCallerResetReachesDestination(t *testing.T) {
	h := newHarness(t, harnessConfig{})
	p := h.open("db.internal", 5432)
	dst := h.accept()
	defer func() { _ = dst.Close() }()
	_ = p.body.CloseWithError(errors.New("caller gave up")) // RST_STREAM
	_ = dst.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := io.ReadAll(dst)
	if err == nil {
		t.Fatal("destination saw a clean FIN after the caller reset")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("destination never saw the caller's reset")
	}
}

// A destination that stops reading must stop the caller without stalling
// other pipes on the same connection.
func TestStalledPipeDoesNotBlockOthers(t *testing.T) {
	h := newHarness(t, harnessConfig{})
	stalled := h.open("stalled.internal", 5432)
	stalledDst := h.accept()
	defer func() { _ = stalledDst.Close() }()
	go func() {
		chunk := make([]byte, 64<<10)
		for {
			if _, err := stalled.body.Write(chunk); err != nil {
				return
			}
		}
	}()
	time.Sleep(200 * time.Millisecond) // let the stalled pipe fill its window

	p := h.open("db.internal", 5432)
	dst := h.accept()
	defer func() { _ = dst.Close() }()
	if _, err := p.body.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	_ = dst.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(dst, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("second pipe stalled behind the first: %q, %v", buf, err)
	}
	_ = stalled.body.CloseWithError(errors.New("done"))
}

func TestRefusals(t *testing.T) {
	tests := []struct {
		name      string
		authority string
		token     func(t *testing.T) string
		setup     func(h *harness)
		status    int
		reason    string
	}{
		{
			name:      "missing capability",
			authority: "db.internal:5432",
			token:     func(*testing.T) string { return "" },
			status:    401,
			reason:    "invalid_capability",
		},
		{
			name:      "capability for another destination",
			authority: "db.internal:5432",
			token:     func(t *testing.T) string { return capabilityFor(t, "other.internal", 5432) },
			status:    403,
			reason:    "wrong_destination",
		},
		{
			name:      "capability for another connector",
			authority: "db.internal:5432",
			token: func(t *testing.T) string {
				return capabilityFor(t, "db.internal", 5432, func(c *capability.Claims) {
					c.ConnectorID = "99999999-2222-4333-8444-555555555555"
				})
			},
			status: 403,
			reason: "wrong_connector",
		},
		{
			name:      "expired capability",
			authority: "db.internal:5432",
			token: func(t *testing.T) string {
				return capabilityFor(t, "db.internal", 5432, func(c *capability.Claims) {
					c.IssuedAt -= 600
					c.ExpiresAt -= 600
				})
			},
			status: 401,
			reason: "capability_expired",
		},
		{
			name:      "non-canonical port",
			authority: "db.internal:05432",
			token:     func(t *testing.T) string { return capabilityFor(t, "db.internal", 5432) },
			status:    400,
			reason:    "protocol_error",
		},
		{
			name:      "name resolving to loopback",
			authority: "sneaky.internal:5432",
			token:     func(t *testing.T) string { return capabilityFor(t, "sneaky.internal", 5432) },
			setup:     func(h *harness) { h.resolved["sneaky.internal"] = "127.0.0.1" },
			status:    403,
			reason:    "forbidden_address",
		},
		{
			name:      "metadata service",
			authority: "169.254.169.254:80",
			token:     func(t *testing.T) string { return capabilityFor(t, "169.254.169.254", 80) },
			status:    403,
			reason:    "forbidden_address",
		},
		{
			name:      "redacted host",
			authority: "redacted.internal:443",
			token:     func(t *testing.T) string { return capabilityFor(t, "redacted.internal", 443) },
			status:    403,
			reason:    "inspection_required",
		},
		{
			name:      "draining",
			authority: "db.internal:5432",
			token:     func(t *testing.T) string { return capabilityFor(t, "db.internal", 5432) },
			setup:     func(h *harness) { h.server.Drain() },
			status:    503,
			reason:    "connector_draining",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, harnessConfig{
				inspect: func(host string, _ uint16) bool { return host == "redacted.internal" },
			})
			if tt.setup != nil {
				tt.setup(h)
			}
			p, err := h.connect(tt.authority, tt.token(t))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = p.resp.Body.Close() }()
			if p.resp.StatusCode != tt.status || p.resp.Header.Get(HeaderReason) != tt.reason {
				t.Fatalf("got %d %q, want %d %q", p.resp.StatusCode,
					p.resp.Header.Get(HeaderReason), tt.status, tt.reason)
			}
		})
	}
}

func TestCapacity(t *testing.T) {
	h := newHarness(t, harnessConfig{maxPipes: 1})
	first := h.open("db.internal", 5432)
	dst := h.accept()
	defer func() { _ = dst.Close() }()

	p, err := h.connect("db.internal:5432", capabilityFor(t, "db.internal", 5432))
	if err != nil {
		t.Fatal(err)
	}
	if p.resp.StatusCode != 503 || p.resp.Header.Get(HeaderReason) != "capacity" {
		t.Fatalf("over the cap: %d %q", p.resp.StatusCode, p.resp.Header.Get(HeaderReason))
	}

	// Closing the first pipe frees its slot.
	_ = first.body.Close()
	_ = dst.CloseWrite()
	_, _ = io.ReadAll(first.resp.Body)
	deadline := time.Now().Add(5 * time.Second)
	for h.server.Open() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	h.open("db.internal", 5432)
}

// One capability opens at most MaxOpensPerToken pipes on this connector.
func TestCapabilityOpenLimit(t *testing.T) {
	h := newHarness(t, harnessConfig{maxPipes: capability.MaxOpensPerToken + 8})
	token := capabilityFor(t, "db.internal", 5432)
	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := h.dest.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	statuses := make(chan string, capability.MaxOpensPerToken+1)
	for range capability.MaxOpensPerToken + 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := h.connect("db.internal:5432", token)
			if err != nil {
				statuses <- err.Error()
				return
			}
			statuses <- p.resp.Header.Get(HeaderReason)
			_ = p.body.Close()
			_ = p.resp.Body.Close()
		}()
	}
	wg.Wait()
	close(statuses)
	exhausted := 0
	for s := range statuses {
		if s == "capability_exhausted" {
			exhausted++
		}
	}
	if exhausted != 1 {
		t.Fatalf("%d opens refused as exhausted, want exactly 1", exhausted)
	}
}

func TestMaxLifetimeAbortsPipe(t *testing.T) {
	h := newHarness(t, harnessConfig{maxLifetime: 200 * time.Millisecond})
	p := h.open("db.internal", 5432)
	dst := h.accept()
	defer func() { _ = dst.Close() }()
	_, err := io.ReadAll(p.resp.Body)
	if err == nil {
		t.Fatal("a pipe cut at its lifetime cap looked like a clean close")
	}
}

// The destination ends its side and then fails while the caller is still
// sending. The caller must be told, as a reset, rather than keep writing into
// a pipe whose bytes go nowhere.
func TestDestinationFailureAfterItsFINResetsCaller(t *testing.T) {
	h := newHarness(t, harnessConfig{})
	p := h.open("db.internal", 5432)
	dst := h.accept()
	_, _ = dst.Write([]byte("done"))
	_ = dst.Close() // FIN; writes that follow get a TCP reset
	got := make([]byte, 4)
	if _, err := io.ReadFull(p.resp.Body, got); err != nil || string(got) != "done" {
		t.Fatalf("read %q, %v", got, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	chunk := bytes.Repeat([]byte("x"), 32<<10)
	for time.Now().Before(deadline) {
		if _, err := p.body.Write(chunk); err != nil {
			return // the stream was reset
		}
	}
	t.Fatal("the caller kept writing for 10 s after the destination failed")
}
