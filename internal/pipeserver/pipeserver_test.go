package pipeserver

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	testpb "google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/metadata"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
	"github.com/InteractionLabs/traversal-connector/connector-lib/halfconn"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe/rawpipetest"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
	"github.com/InteractionLabs/traversal-connector/internal/upstream"
)

const connector = "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d00"

// harness is a connector's pipe server on one tunnel, with the Integration
// Proxy's side of each pipe: rawpipe.Connect, then PipeClientTLS, as the
// proxy does it.
type harness struct {
	t       *testing.T
	tunnels *Tunnels
	cc      *http.ClientConn
	key     *ecdsa.PrivateKey
	tenant  *rawpipetest.CA
	// dest is the address every destination dials, standing in for the dial
	// policy, which refuses loopback.
	dest string
}

func newHarness(t *testing.T, cfg *config.Config, r *redact.Redactor, dest string) *harness {
	t.Helper()
	if cfg == nil {
		cfg = &config.Config{UpstreamTLSVerify: true, RequestTimeout: 5 * time.Second,
			MaxResponseBodySizeMB: 1, MaxDecodedResponseBodySizeMB: 4}
	}
	if r == nil {
		r = redact.NewRedactor()
	}
	h := &harness{t: t, key: capabilitytest.Key("pipeserver"), tenant: rawpipetest.NewCA(t),
		dest: dest}
	verifier, err := capability.NewVerifier(capability.VerifierConfig{
		Issuer: "traversal-raw-tunnel/test", Subject: capability.SubjectIntegrationProxy,
		Keys: map[string]*ecdsa.PublicKey{"k": &h.key.PublicKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	up, err := upstream.New(cfg, r, h.dial)
	if err != nil {
		t.Fatal(err)
	}
	cert := h.tenant.Connector(t, "spiffe://traversal.com/tenant/"+org+"/acme",
		time.Now().Add(time.Hour))
	h.tunnels = &Tunnels{ConnectorID: connector, Count: 1, Kids: []string{"k"},
		Server: &Server{ConnectorID: connector, Verifier: verifier, Upstream: up,
			Certificate: cert, MaxPipes: 16, metrics: testMetrics(t),
			Inner: Inner{MaxStreams: 100, StreamWindow: 256 << 10, ConnectionWindow: 1 << 20},
			Ready: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `{"status":"ready"}`)
			}),
		}}
	accept := controller(t, h.tunnels)
	ctx, cancel := context.WithCancel(t.Context())
	done := h.tunnels.Start(ctx)
	t.Cleanup(func() { cancel(); <-done })
	h.cc = accept()
	return h
}

func (h *harness) dial(ctx context.Context, _ string, _ uint16) (halfconn.Conn, string, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", h.dest)
	if err != nil {
		return nil, "", rawpipe.Errorf(rawpipe.DialFailed, "%v", err)
	}
	return c.(*net.TCPConn), h.dest, nil //nolint:forcetypeassert // tcp
}

func (h *harness) token(host string, port uint16) string {
	tok, err := capability.Sign(h.key, "k",
		capabilitytest.Claims("traversal-raw-tunnel/test", connector, host, port))
	if err != nil {
		h.t.Fatal(err)
	}
	return tok
}

// open opens a pipe to authority and does its TLS with tlsCfg, or the proxy's
// own (PipeClientTLS for this connector) if nil.
func (h *harness) open(authority string, tlsCfg *tls.Config) (*tls.Conn, error) {
	host, port, _ := capability.SplitAuthority(authority)
	stream, err := rawpipe.Connect(h.t.Context(), h.cc, "tunnel", authority,
		http.Header{rawpipe.HeaderCapability: {h.token(host, port)}}, 5*time.Second)
	if err != nil {
		return nil, err
	}
	h.t.Cleanup(stream.Close)
	if tlsCfg == nil {
		tlsCfg = rawpipe.PipeClientTLS(h.tenant.Pool(), org, connector)
	}
	tc := tls.Client(halfconn.NewStreamConn(stream), tlsCfg)
	if err := tc.HandshakeContext(h.t.Context()); err != nil {
		return nil, err
	}
	h.t.Cleanup(func() { _ = tc.Close() })
	return tc, nil
}

// client is an HTTP client whose every connection is a new pipe to
// authority: h2 naming the URL's scheme in rawpipe.HeaderUpstreamScheme, or
// HTTP/1.1 in absolute form, as a forward proxy client sends it.
func (h *harness) client(authority string, http1 bool) *http.Client {
	if http1 {
		return &http.Client{Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: "pipe"}),
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				cfg := rawpipe.PipeClientTLS(h.tenant.Pool(), org, connector)
				cfg.NextProtos = []string{rawpipe.ALPNHTTP1}
				return h.open(authority, cfg)
			},
		}}
	}
	return &http.Client{Transport: upstreamScheme{h.h2(authority)}}
}

// h2 is an HTTP/2 transport whose every connection is a new pipe to
// authority, for http:// and https:// URLs alike: the URL's scheme is the
// destination's, and the pipe's TLS is the same either way.
func (h *harness) h2(authority string) *http.Transport {
	open := func(context.Context, string, string) (net.Conn, error) {
		tc, err := h.open(authority, nil)
		if err != nil {
			return nil, err
		}
		// Prior knowledge for http:// URLs: the pipe's TLS chose h2.
		return struct{ net.Conn }{tc}, nil
	}
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	return &http.Transport{Protocols: protocols, DialContext: open, DialTLSContext: open}
}

// upstreamScheme sets rawpipe.HeaderUpstreamScheme to each request's URL
// scheme, as the Integration Proxy does.
type upstreamScheme struct{ http.RoundTripper }

func (u upstreamScheme) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set(rawpipe.HeaderUpstreamScheme, r.URL.Scheme)
	return u.RoundTripper.RoundTrip(r)
}

// controller listens for a tunnel and points tunnels at itself. accept takes
// the tunnel, checks its preface reports the tunnels' connector and trust,
// and returns an HTTP/2 client on it, as the edge controller does.
func controller(t *testing.T, tunnels *Tunnels) (accept func() *http.ClientConn) {
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
	return func() *http.ClientConn {
		c, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		h, err := rawpipe.ReadPreface(bufio.NewReader(c))
		if err != nil || h.ConnectorID != connector || !slices.Equal(h.Roots, tunnels.Roots) ||
			!slices.Equal(h.Kids, tunnels.Kids) {
			t.Fatalf("preface %+v: %v", h, err)
		}
		return h2Client(t, c)
	}
}

// h2Client is an HTTP/2 client with prior knowledge on c, as the edge
// controller speaks on a tunnel.
func h2Client(t *testing.T, c net.Conn) *http.ClientConn {
	t.Helper()
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	tr := &http.Transport{Protocols: protocols,
		DialContext: func(context.Context, string, string) (net.Conn, error) { return c, nil }}
	cc, err := tr.NewClientConn(t.Context(), "http", "tunnel:80")
	if err != nil {
		t.Fatal(err)
	}
	return cc
}

// testMetrics are the pipe metrics on the global meter, a no-op in tests.
func testMetrics(t *testing.T) *metrics {
	t.Helper()
	m, err := newMetrics()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestPipeRefusals: an open is refused before any TLS or dial for a bad
// capability, the probe name on another port, and while draining.
func TestPipeRefusals(t *testing.T) {
	h := newHarness(t, nil, nil, "127.0.0.1:1")
	refusal := func(authority, token string) rawpipe.Reason {
		t.Helper()
		_, err := rawpipe.Connect(t.Context(), h.cc, "tunnel", authority,
			http.Header{rawpipe.HeaderCapability: {token}}, 5*time.Second)
		r, ok := errors.AsType[*rawpipe.Refusal](err)
		if !ok {
			t.Fatalf("%s: %v, want a refusal", authority, err)
		}
		return r.Reason
	}
	if r := refusal("db.internal:443", "bogus"); r != rawpipe.InvalidCapability {
		t.Errorf("bad capability: %s", r)
	}
	if r := refusal(rawpipe.ProbeHost+":80", h.token(rawpipe.ProbeHost, 80)); r != rawpipe.WrongDestination {
		t.Errorf("probe host on port 80: %s", r)
	}
	h.tunnels.Server.pipes.Drain()
	if r := refusal("db.internal:443", h.token("db.internal", 443)); r != rawpipe.Draining {
		t.Errorf("draining: %s", r)
	}
}

// TestPipeTLSIdentity: the proxy refuses a connector whose certificate is
// not from its tenant's CA, or names another org. (The connector-scoped
// cases are rawpipe's TestPipeTLS.)
func TestPipeTLSIdentity(t *testing.T) {
	h := newHarness(t, nil, nil, "127.0.0.1:1")
	for name, cfg := range map[string]*tls.Config{
		"another tenant CA": rawpipe.PipeClientTLS(rawpipetest.NewCA(t).Pool(), org, connector),
		"another org": rawpipe.PipeClientTLS(h.tenant.Pool(),
			strings.Replace(org, "0b", "1b", 1), connector),
	} {
		if _, err := h.open("db.internal:443", cfg); err == nil {
			t.Errorf("%s: handshake succeeded", name)
		}
	}
}

// TestRequestRouting: a request inside a pipe goes only to the pipe's
// destination, with TLS by its scheme, and probes are answered without a
// dial.
func TestRequestRouting(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		// The body is text/plain, so the host and path in it are no XSS.
		_, _ = fmt.Fprintf(w, "plain %s%s", r.Host, r.URL.Path) //nolint:gosec // text/plain
	}))
	t.Cleanup(plain.Close)
	h := newHarness(t, nil, nil, plain.Listener.Addr().String())
	for _, c := range []struct {
		name, authority, url string
		http1                bool
		status               int
		body                 string
	}{
		{"h2, http scheme", "api.internal:80", "http://api.internal/x", false, 200, "plain api.internal/x"},
		{"HTTP/1.1, absolute form", "api.internal:80", "http://api.internal/x", true, 200,
			"plain api.internal/x"},
		{"another host", "api.internal:80", "http://other.internal/x", false, 403, ""},
		{"another port", "api.internal:80", "http://api.internal:81/x", true, 403, ""},
		{"probe", rawpipe.ProbeAuthority, "https://" + rawpipe.ProbeHost + rawpipe.ProbePath, false,
			200, `{"status":"ready"}`},
		{"probe, another path", rawpipe.ProbeAuthority, "https://" + rawpipe.ProbeHost + "/x", false,
			404, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			resp, err := h.client(c.authority, c.http1).Get(c.url)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != c.status || c.body != "" && string(body) != c.body {
				t.Fatalf("%d %q, want %d %q", resp.StatusCode, body, c.status, c.body)
			}
			if c.status == 403 &&
				resp.Header.Get(rawpipe.HeaderReason) != string(rawpipe.WrongDestination) {
				t.Fatalf("reason %q", resp.Header.Get(rawpipe.HeaderReason))
			}
		})
	}
}

// TestUpstreamSchemeHeader: an HTTP/2 request's destination scheme is
// rawpipe.HeaderUpstreamScheme, https when absent (so port 443), anything
// but http or https is refused, and the header is not forwarded.
func TestUpstreamSchemeHeader(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get(rawpipe.HeaderUpstreamScheme); v != "" {
			t.Errorf("the destination got %s: %q", rawpipe.HeaderUpstreamScheme, v)
		}
		_, _ = io.WriteString(w, "plain")
	}))
	t.Cleanup(plain.Close)
	h := newHarness(t, nil, nil, plain.Listener.Addr().String())
	for _, c := range []struct {
		name, scheme string
		status       int
		reason       rawpipe.Reason
	}{
		{"http", "http", 200, ""},
		{"absent is https, so port 443", "", 403, rawpipe.WrongDestination},
		{"neither http nor https", "ftp", 400, rawpipe.ProtocolError},
	} {
		t.Run(c.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "http://api.internal/x", http.NoBody)
			if c.scheme != "" {
				req.Header.Set(rawpipe.HeaderUpstreamScheme, c.scheme)
			}
			resp, err := h.h2("api.internal:80").RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != c.status ||
				resp.Header.Get(rawpipe.HeaderReason) != string(c.reason) {
				t.Fatalf("%d %q, want %d %q", resp.StatusCode,
					resp.Header.Get(rawpipe.HeaderReason), c.status, c.reason)
			}
		})
	}
}

// TestNoConnectInPipe: a pipe is HTTP to its destination; CONNECT inside it
// would make it a byte pipe again, past redaction.
func TestNoConnectInPipe(t *testing.T) {
	dest := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("CONNECT reached the destination")
	}))
	t.Cleanup(dest.Close)
	h := newHarness(t, nil, nil, dest.Listener.Addr().String())
	conn, err := h.open("db.internal:5432", nil)
	if err != nil {
		t.Fatal(err)
	}
	cc := h2Client(t, conn)
	req, _ := http.NewRequest(http.MethodConnect, "https://db.internal:5432", http.NoBody)
	req.Host = "db.internal:5432"
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest ||
		resp.Header.Get(rawpipe.HeaderReason) != string(rawpipe.ProtocolError) {
		t.Fatalf("%d %q", resp.StatusCode, resp.Header.Get(rawpipe.HeaderReason))
	}
}

// TestCustomerCA: TLS toward the server is verified with the customer's CA,
// and refused without it.
func TestCustomerCA(t *testing.T) {
	ca := rawpipetest.NewCA(t)
	srv := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "verified")
		}),
	)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.Server(t, "api.internal")}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}))
	for name, c := range map[string]struct {
		ca     *string
		status int
	}{"customer CA": {&caPEM, 200}, "system roots only": {nil, 502}} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, &config.Config{UpstreamTLSVerify: true, UpstreamTLSCA: c.ca,
				RequestTimeout: 5 * time.Second}, nil, srv.Listener.Addr().String())
			resp, err := h.client("api.internal:443", false).Get("https://api.internal/")
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != c.status {
				t.Fatalf("%d, want %d", resp.StatusCode, c.status)
			}
			if c.status == 502 &&
				resp.Header.Get(rawpipe.HeaderReason) != string(rawpipe.UpstreamFailed) {
				t.Fatalf("reason %q", resp.Header.Get(rawpipe.HeaderReason))
			}
		})
	}
}

// TestStreamed: with no rules for the host, the first bytes of a response
// arrive while the server is still writing it.
func TestStreamed(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "data: last\n\n")
	}))
	t.Cleanup(srv.Close)
	defer close(release)
	h := newHarness(t, nil, nil, srv.Listener.Addr().String())
	resp, err := h.client("events.internal:80", false).Get("http://events.internal/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != "data: first\n" {
		t.Fatalf("first event %q %v, before the server finished", line, err)
	}
}

// TestUploadStreamed: a request body reaches the destination while the
// client is still sending it, and one past MAX_REQUEST_BODY_SIZE_MB is cut
// off before the destination has it all.
func TestUploadStreamed(t *testing.T) {
	got := make(chan int64, 1)
	first := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.CopyN(io.Discard, r.Body, 1)
		select {
		case first <- struct{}{}:
		default:
		}
		m, _ := io.Copy(io.Discard, r.Body)
		got <- n + m
	}))
	t.Cleanup(srv.Close)
	h := newHarness(t, &config.Config{RequestTimeout: 5 * time.Second, MaxRequestBodySizeMB: 1},
		nil, srv.Listener.Addr().String())
	client := h.client("upload.internal:80", false)
	upload := func(size int, hold bool) int64 {
		pr, pw := io.Pipe()
		go func() {
			_, _ = pw.Write(make([]byte, 1))
			if hold {
				<-first
			}
			_, _ = pw.Write(make([]byte, size-1))
			_ = pw.Close()
		}()
		resp, err := client.Post("http://upload.internal/", "application/octet-stream", pr)
		if err == nil {
			_ = resp.Body.Close()
		}
		return <-got
	}
	if n := upload(512<<10, true); n != 512<<10 {
		t.Fatalf("upload: the destination got %d bytes", n)
	}
	if n := upload(2<<20, false); n >= 2<<20 {
		t.Fatalf("an upload past the limit arrived whole: %d bytes", n)
	}
}

// TestRedaction: a covered host's text is buffered and redacted; its gRPC,
// binary, or endless responses are refused as redaction_unsupported, never
// sent as they came.
func TestRedaction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/text":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "contact user@example.com")
		case "/binary":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, "contact user@example.com")
		case "/endless":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "contact user@example.com")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case "/grpc":
			t.Error("a gRPC request to a covered host reached it")
		}
	}))
	t.Cleanup(srv.Close)
	r := redact.NewRedactor()
	if err := r.Update(&redact.RulesFile{Version: "v1", Rules: []redact.Rule{{Name: "email",
		Type: "regex", Pattern: `[a-z]+@[a-z.]+`, Replacement: "[REDACTED]",
		Hosts: []string{`covered\.internal`}}}}); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, &config.Config{RequestTimeout: 500 * time.Millisecond,
		MaxResponseBodySizeMB: 1, MaxDecodedResponseBodySizeMB: 4}, r, srv.Listener.Addr().String())
	client := h.client("covered.internal:80", false)
	for _, c := range []struct {
		path, contentType string
		status            int
		body              string
	}{
		{"/text", "", 200, "contact [REDACTED]"},
		{"/binary", "", 502, ""},
		{"/endless", "", 502, ""},
		{"/grpc", "application/grpc", 502, ""},
	} {
		req, _ := http.NewRequest(http.MethodGet, "http://covered.internal"+c.path, nil)
		if c.contentType != "" {
			req.Header.Set("Content-Type", c.contentType)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		switch {
		case resp.StatusCode != c.status:
			t.Errorf("%s: %d %q, want %d", c.path, resp.StatusCode, body, c.status)
		case c.status == 200 && (string(body) != c.body || resp.Header.Get("X-Traversal-Redacted") != "true"):
			t.Errorf("%s: %q %v", c.path, body, resp.Header)
		case c.status == 502 && resp.Header.Get(rawpipe.HeaderReason) != string(rawpipe.RedactionUnsupported):
			t.Errorf("%s: reason %q", c.path, resp.Header.Get(rawpipe.HeaderReason))
		case strings.Contains(string(body), "user@example.com"):
			t.Errorf("%s: unredacted %q", c.path, body)
		}
	}
}

// TestGRPCBidi: a bidirectional gRPC stream through a pipe, each message
// answered before the next is sent, with its trailers.
func TestGRPCBidi(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	testpb.RegisterTestServiceServer(gs, echoService{})
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(gs.Stop)
	h := newHarness(t, nil, nil, ln.Addr().String())
	cc, err := grpc.NewClient("passthrough:///grpc.internal:80",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return h.open("grpc.internal:80", nil)
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	// The destination is plaintext gRPC; the proxy names the scheme.
	ctx := metadata.AppendToOutgoingContext(t.Context(),
		strings.ToLower(rawpipe.HeaderUpstreamScheme), "http")
	stream, err := testpb.NewTestServiceClient(cc).FullDuplexCall(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range []string{"one", "two", "three"} {
		if err := stream.Send(&testpb.StreamingOutputCallRequest{
			Payload: &testpb.Payload{Body: []byte(msg)}}); err != nil {
			t.Fatal(err)
		}
		resp, err := stream.Recv()
		if err != nil || string(resp.GetPayload().GetBody()) != msg {
			t.Fatalf("echo of %q: %v %v", msg, resp, err)
		}
	}
	_ = stream.CloseSend()
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("end of stream: %v", err)
	}
	if got := stream.Trailer().Get("x-echo"); len(got) != 1 || got[0] != "3" {
		t.Fatalf("trailer %v", stream.Trailer())
	}
}

// echoService echoes each FullDuplexCall message and sets a trailer counting
// them.
type echoService struct {
	testpb.UnimplementedTestServiceServer
}

func (echoService) FullDuplexCall(
	s grpc.BidiStreamingServer[testpb.StreamingOutputCallRequest, testpb.StreamingOutputCallResponse],
) error {
	n := 0
	for {
		req, err := s.Recv()
		if errors.Is(err, io.EOF) {
			s.SetTrailer(metadata.Pairs("x-echo", strconv.Itoa(n)))
			return nil
		}
		if err != nil {
			return err
		}
		n++
		if err := s.Send(&testpb.StreamingOutputCallResponse{Payload: req.GetPayload()}); err != nil {
			return err
		}
	}
}

// TestWebSocket: an Upgrade over HTTP/1.1 is a byte stream both ways after
// the 101.
func TestWebSocket(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "upgrade required", http.StatusUpgradeRequired)
			return
		}
		c, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"+
			"Connection: Upgrade\r\n\r\n")
		line, _ := rw.ReadString('\n')
		_, _ = io.WriteString(c, strings.ToUpper(line))
	}))
	t.Cleanup(srv.Close)
	h := newHarness(t, nil, nil, srv.Listener.Addr().String())
	cfg := rawpipe.PipeClientTLS(h.tenant.Pool(), org, connector)
	cfg.NextProtos = []string{rawpipe.ALPNHTTP1}
	conn, err := h.open("ws.internal:80", cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(conn, "GET http://ws.internal/ HTTP/1.1\r\nHost: ws.internal\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	defer resp.Body.Close()
	_, _ = io.WriteString(conn, "frame\n")
	if line, err := br.ReadString('\n'); err != nil || line != "FRAME\n" {
		t.Fatalf("after the 101: %q %v", line, err)
	}
}

// TestRedial: a tunnel the edge controller drops is redialed, and a drain
// request gets a replacement at once while the old tunnel stays open.
func TestRedial(t *testing.T) {
	tunnels := &Tunnels{ConnectorID: connector, Count: 1,
		Server: &Server{ConnectorID: connector, metrics: testMetrics(t)}}
	accept := controller(t, tunnels)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tunnels.Start(ctx)
	next := func(within time.Duration) *http.ClientConn {
		t.Helper()
		got := make(chan *http.ClientConn, 1)
		go func() { got <- accept() }()
		select {
		case cc := <-got:
			return cc
		case <-time.After(within):
			t.Fatalf("no tunnel within %v", within)
			return nil
		}
	}
	first := next(5 * time.Second)
	_ = first.Close() // the edge controller drops the tunnel
	second := next(5 * time.Second)

	req, _ := http.NewRequest(rawpipe.DrainMethod, "http://tunnel/", http.NoBody)
	resp, err := second.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	next(500 * time.Millisecond) // the replacement comes without backoff
	if second.Available() == 0 {
		t.Error("the replaced tunnel closed before the edge controller closed it")
	}
}

// TestTunnelServerLimits: the tunnel advertises the connector's pipe limit
// per tunnel (so opens past it are capacity refusals, not open timeouts),
// and pings a quiet tunnel so a dead far end is found.
func TestTunnelServerLimits(t *testing.T) {
	s := &Server{MaxPipes: 4000, Tunnels: 2}
	h := s.h2()
	if h.MaxConcurrentStreams < 2000 || h.MaxConcurrentStreams > 2100 {
		t.Errorf("MaxConcurrentStreams = %d for 4000 pipes over 2 tunnels", h.MaxConcurrentStreams)
	}
	if h.SendPingTimeout == 0 || h.PingTimeout == 0 {
		t.Error("no read-idle ping: a tunnel to a dead controller would be held forever")
	}
	if h.MaxReceiveBufferPerStream > 1<<20 {
		t.Errorf("per-stream window %d: a stalled pipe holds too much", h.MaxReceiveBufferPerStream)
	}
}

// TestReadyAfterFirstTunnel: once a tunnel has been up, losing tunnels (a
// controller rollout) does not make the connector unready.
func TestReadyAfterFirstTunnel(t *testing.T) {
	tunnels := &Tunnels{}
	if ok, _ := tunnels.Ready(t.Context()); ok {
		t.Error("ready before any tunnel")
	}
	tunnels.everUp.Store(true)
	if ok, _ := tunnels.Ready(t.Context()); !ok {
		t.Error("unready after tunnels flapped")
	}
}
