package pipeserver

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"
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

const (
	org       = "0b6e5a3c-1d2f-4a5b-8c7d-9e0f1a2b3c4d"
	connector = "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d00"
)

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
			PipeLimits: PipeLimits{
				MaxStreams:       100,
				StreamWindow:     256 << 10,
				ConnectionWindow: 1 << 20,
			},
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
