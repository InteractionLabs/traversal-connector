package pipeserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	testpb "google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/metadata"

	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe/rawpipetest"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
)

// TestRequestRouting: a request inside a pipe goes only to the pipe's
// destination, with TLS by its scheme, and probes are answered without a
// dial. On h2 the scheme is rawpipe.HeaderUpstreamScheme, https when absent,
// and is not forwarded; CONNECT inside a pipe, which would make it a byte
// pipe again past redaction, is refused.
func TestRequestRouting(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			t.Error("CONNECT reached the destination")
		}
		w.Header().Set("Content-Type", "text/plain")
		// The body is text/plain, so the host and path in it are no XSS.
		_, _ = fmt.Fprintf(w, "plain %s%s %s", r.Host, r.URL.Path, //nolint:gosec // text/plain
			r.Header.Get(rawpipe.HeaderUpstreamScheme))
	}))
	t.Cleanup(plain.Close)
	h := newHarness(t, nil, nil, plain.Listener.Addr().String())
	// get is a GET of url through a pipe to authority: h2 naming scheme in
	// rawpipe.HeaderUpstreamScheme ("-" for none), or HTTP/1.1 in absolute
	// form.
	get := func(authority, url, scheme string, http1 bool) (*http.Response, error) {
		req, _ := http.NewRequest(http.MethodGet, url, http.NoBody)
		switch {
		case http1:
			return h.client(authority, true).Do(req)
		case scheme != "-":
			req.Header.Set(rawpipe.HeaderUpstreamScheme, scheme)
		}
		return h.h2(authority).RoundTrip(req)
	}
	connect := func(authority string) (*http.Response, error) {
		conn, err := h.open(authority, nil)
		if err != nil {
			return nil, err
		}
		req, _ := http.NewRequest(http.MethodConnect, "https://"+authority, http.NoBody)
		req.Host = authority
		return h2Client(t, conn).RoundTrip(req)
	}
	for _, c := range []struct {
		name string
		send func() (*http.Response, error)
		// status and reason are the answer; body, if set, the destination's.
		status int
		reason rawpipe.Reason
		body   string
	}{
		{"h2, http scheme", func() (*http.Response, error) {
			return get("api.internal:80", "http://api.internal/x", "http", false)
		}, 200, "", "plain api.internal/x "},
		{"HTTP/1.1, absolute form", func() (*http.Response, error) {
			return get("api.internal:80", "http://api.internal/x", "", true)
		}, 200, "", "plain api.internal/x "},
		{"another host", func() (*http.Response, error) {
			return get("api.internal:80", "http://other.internal/x", "http", false)
		}, 403, rawpipe.WrongDestination, ""},
		{"another port", func() (*http.Response, error) {
			return get("api.internal:80", "http://api.internal:81/x", "", true)
		}, 403, rawpipe.WrongDestination, ""},
		{"no scheme header is https, so port 443", func() (*http.Response, error) {
			return get("api.internal:80", "http://api.internal/x", "-", false)
		}, 403, rawpipe.WrongDestination, ""},
		{"scheme neither http nor https", func() (*http.Response, error) {
			return get("api.internal:80", "http://api.internal/x", "ftp", false)
		}, 400, rawpipe.ProtocolError, ""},
		{"CONNECT inside a pipe", func() (*http.Response, error) {
			return connect("db.internal:5432")
		}, 400, rawpipe.ProtocolError, ""},
		{"probe", func() (*http.Response, error) {
			return get(rawpipe.ProbeAuthority, "https://"+rawpipe.ProbeHost+rawpipe.ProbePath, "-", false)
		}, 200, "", `{"status":"ready"}`},
		{"probe, another path", func() (*http.Response, error) {
			return get(rawpipe.ProbeAuthority, "https://"+rawpipe.ProbeHost+"/x", "-", false)
		}, 404, "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			resp, err := c.send()
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != c.status || c.body != "" && string(body) != c.body ||
				resp.Header.Get(rawpipe.HeaderReason) != string(c.reason) {
				t.Fatalf("%d %q %q, want %d %q %q", resp.StatusCode,
					resp.Header.Get(rawpipe.HeaderReason), body, c.status, c.reason, c.body)
			}
		})
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

// TestBodyLimits: every buffer a pipe fills for a covered host is finite.
// A request over MAX_REQUEST_BODY_SIZE_MB by its Content-Length, or with
// headers well over net/http's default limit, is refused before it reaches the
// destination; a response over MAX_RESPONSE_BODY_SIZE_MB, with a length or
// chunked, is refused as redaction_unsupported, not read to its end.
func TestBodyLimits(t *testing.T) {
	const limit = 1 << 20
	reached := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached <- r.URL.Path
		w.Header().Set("Content-Type", "text/plain")
		switch r.URL.Path {
		case "/big":
			_, _ = io.WriteString(w, strings.Repeat("a", limit+1))
		case "/big-chunked":
			// No Content-Length: the response is chunked, of unknown length.
			for range 3 {
				_, _ = io.WriteString(w, strings.Repeat("a", limit/2))
				w.(http.Flusher).Flush() //nolint:forcetypeassert // httptest
			}
		}
	}))
	t.Cleanup(srv.Close)
	r := redact.NewRedactor()
	if err := r.Update(&redact.RulesFile{Version: "v1", Rules: []redact.Rule{{Name: "email",
		Type: "regex", Pattern: `[a-z]+@[a-z.]+`, Hosts: []string{`covered\.internal`}}}}); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, &config.Config{RequestTimeout: 5 * time.Second, MaxRequestBodySizeMB: 1,
		MaxResponseBodySizeMB: 1, MaxDecodedResponseBodySizeMB: 1}, r, srv.Listener.Addr().String())
	for _, c := range []struct {
		name, method, path string
		body               string
		header             string
		http1              bool
		status             int
		reason             rawpipe.Reason
	}{
		{name: "request body by Content-Length", method: http.MethodPost, path: "/r",
			body: strings.Repeat("a", limit+1), status: http.StatusRequestEntityTooLarge},
		{name: "request headers", method: http.MethodGet, path: "/r", http1: true,
			header: strings.Repeat("a", 2*http.DefaultMaxHeaderBytes),
			status: http.StatusRequestHeaderFieldsTooLarge},
		{name: "response body", method: http.MethodGet, path: "/big",
			status: http.StatusBadGateway, reason: rawpipe.RedactionUnsupported},
		{name: "chunked response body", method: http.MethodGet, path: "/big-chunked",
			status: http.StatusBadGateway, reason: rawpipe.RedactionUnsupported},
	} {
		t.Run(c.name, func(t *testing.T) {
			var body io.Reader
			if c.body != "" {
				body = strings.NewReader(c.body)
			}
			req, _ := http.NewRequest(c.method, "http://covered.internal"+c.path, body)
			if c.header != "" {
				req.Header.Set("X-Pad", c.header)
			}
			resp, err := h.client("covered.internal:80", c.http1).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != c.status {
				t.Fatalf("%d %.80q, want %d", resp.StatusCode, got, c.status)
			}
			if c.reason != "" && resp.Header.Get(rawpipe.HeaderReason) != string(c.reason) {
				t.Fatalf("reason %q, want %q", resp.Header.Get(rawpipe.HeaderReason), c.reason)
			}
			if len(got) > limit {
				t.Fatalf("a body past the limit was sent: %d bytes", len(got))
			}
			wantReached := c.status == http.StatusBadGateway
			select {
			case path := <-reached:
				if !wantReached {
					t.Fatalf("an oversized request reached the destination: %s", path)
				}
			default:
				if wantReached {
					t.Fatal("the request did not reach the destination")
				}
			}
		})
	}
}
