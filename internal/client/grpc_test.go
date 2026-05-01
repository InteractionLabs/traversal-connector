package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/net/http2"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/internal/config"
)

func ptrTo[T any](v T) *T { return &v }

// generateTestKeyPair returns a freshly-generated self-signed cert and key
// as PEM strings. Used by tests that exercise the TLS transport path, since
// tls.X509KeyPair validates that the cert and key actually pair up.
func generateTestKeyPair(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, template, &priv.PublicKey, priv,
	)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: der},
	))
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER},
	))
	return certPEM, keyPEM
}

func TestHttpRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		req     *pb.HttpRequest
		wantErr bool
	}{
		{
			name: "valid GET request",
			req: &pb.HttpRequest{
				Method: "GET",
				Url:    "https://example.com/api",
			},
			wantErr: false,
		},
		{
			name: "valid POST request with body",
			req: &pb.HttpRequest{
				Method: "POST",
				Url:    "https://example.com/api",
				Headers: []*pb.Header{
					{Key: "Content-Type", Value: "application/json"},
				},
				Body: []byte(`{"key":"value"}`),
			},
			wantErr: false,
		},
		{
			name: "all valid methods",
			req: &pb.HttpRequest{
				Method: "OPTIONS",
				Url:    "https://example.com",
			},
			wantErr: false,
		},
		{
			name: "invalid method",
			req: &pb.HttpRequest{
				Method: "INVALID",
				Url:    "https://example.com",
			},
			wantErr: true,
		},
		{
			name: "empty method",
			req: &pb.HttpRequest{
				Method: "",
				Url:    "https://example.com",
			},
			wantErr: true,
		},
		{
			name: "lowercase method rejected",
			req: &pb.HttpRequest{
				Method: "get",
				Url:    "https://example.com",
			},
			wantErr: true,
		},
		{
			name: "empty URL",
			req: &pb.HttpRequest{
				Method: "GET",
				Url:    "",
			},
			wantErr: true,
		},
		{
			name: "valid HEAD request",
			req: &pb.HttpRequest{
				Method: "HEAD",
				Url:    "https://example.com",
			},
			wantErr: false,
		},
		{
			name: "valid DELETE request",
			req: &pb.HttpRequest{
				Method: "DELETE",
				Url:    "https://example.com/resource/123",
			},
			wantErr: false,
		},
		{
			name: "valid PATCH request",
			req: &pb.HttpRequest{
				Method: "PATCH",
				Url:    "https://example.com/resource/123",
			},
			wantErr: false,
		},
		{
			name: "valid PUT request",
			req: &pb.HttpRequest{
				Method: "PUT",
				Url:    "https://example.com/resource/123",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := protovalidate.Validate(tt.req)
			if tt.wantErr && err == nil {
				t.Error("expected validation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestNewTransport_NoProxy(t *testing.T) {
	cfg := &config.Config{
		TraversalControllerURL: "http://localhost:9080",
	}

	transport, err := newTransport(cfg)
	if err != nil {
		t.Fatalf("newTransport() error: %v", err)
	}

	if _, ok := transport.(*http2.Transport); !ok {
		t.Errorf("expected *http2.Transport for no proxy, got %T", transport)
	}
}

func TestNewTransport_WithTLSCertsAndProxy(t *testing.T) {
	certPEM, keyPEM := generateTestKeyPair(t)

	cfg := &config.Config{
		TraversalControllerURL: "https://controller.example.com:9080",
		InternetProxyURL:       ptrTo("http://proxy.example.com:3128"),
		TLSCert:                &certPEM,
		TLSKey:                 &keyPEM,
		TLSServerName:          "controller.example.com",
	}

	transport, err := newTransport(cfg)
	if err != nil {
		t.Fatalf("newTransport() error: %v", err)
	}

	httpTransport, ok := transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport when TLS certs provided, got %T", transport)
	}

	if httpTransport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be set")
	}

	if diff := cmp.Diff(
		"controller.example.com",
		httpTransport.TLSClientConfig.ServerName,
	); diff != "" {
		t.Errorf("TLS ServerName mismatch (-want +got):\n%s", diff)
	}

	if len(httpTransport.TLSClientConfig.Certificates) != 1 {
		t.Errorf(
			"expected exactly 1 client certificate, got %d",
			len(httpTransport.TLSClientConfig.Certificates),
		)
	}

	// Verify the proxy function is set.
	proxyReq, _ := http.NewRequestWithContext(
		context.Background(),
		"GET",
		"https://controller.example.com",
		nil,
	)
	proxyURL, err := httpTransport.Proxy(proxyReq)
	if err != nil {
		t.Fatalf("proxy function returned error: %v", err)
	}
	if proxyURL == nil {
		t.Fatal("expected proxy URL to be set")
	}
	if diff := cmp.Diff("proxy.example.com:3128", proxyURL.Host); diff != "" {
		t.Errorf("proxy host mismatch (-want +got):\n%s", diff)
	}
}

func TestNewTransport_HTTPSWithoutCertsReturnsError(t *testing.T) {
	// In production this configuration is rejected by config.Load; if Load
	// is bypassed, newTransport surfaces the error rather than silently
	// falling back to a misleading transport.
	cfg := &config.Config{
		TraversalControllerURL: "https://controller.example.com:9080",
	}

	if _, err := newTransport(cfg); err == nil {
		t.Fatal("newTransport() returned nil error for https without certs")
	}
}

func TestNewTransport_InvalidProxyURL(t *testing.T) {
	cfg := &config.Config{
		TraversalControllerURL: "http://localhost:9080",
		InternetProxyURL:       ptrTo("://bad-url"),
	}

	transport, err := newTransport(cfg)
	if err != nil {
		t.Fatalf("newTransport() error: %v", err)
	}

	// http URL → h2c regardless of proxy validity.
	if _, ok := transport.(*http2.Transport); !ok {
		t.Errorf("expected *http2.Transport for http URL, got %T", transport)
	}
}

// mockSender captures the last ConnectorMessage passed to Send.
type mockSender struct {
	sent *pb.ConnectorMessage
}

func (m *mockSender) Send(msg *pb.ConnectorMessage) error {
	m.sent = msg
	return nil
}

func newTestConnectionManager() *ConnectionManager {
	return &ConnectionManager{
		config:   &config.Config{MaxConcurrentRequests: 10},
		tracer:   noop.NewTracerProvider().Tracer("test"),
		hostname: "test-host",
	}
}

func TestHandleMessage_MetadataRequest_ReturnsMetadataResponse(t *testing.T) {
	const reqID = "test-meta-req-id"
	connID := uuid.New()

	sender := &mockSender{}
	cm := newTestConnectionManager()

	msg := &pb.ControllerMessage{
		RequestId: reqID,
		Message:   &pb.ControllerMessage_MetadataRequest{MetadataRequest: &pb.MetadataRequest{}},
	}

	if err := cm.handleMessage(context.Background(), sender, connID, msg); err != nil {
		t.Fatalf("handleMessage() = %v", err)
	}

	if sender.sent == nil {
		t.Fatal("expected a message to be sent, got none")
	}
	if diff := cmp.Diff(reqID, sender.sent.RequestId); diff != "" {
		t.Errorf("request_id mismatch (-want +got):\n%s", diff)
	}
	meta := sender.sent.GetMetadataResponse()
	if meta == nil {
		t.Fatalf("expected MetadataResponse, got %T", sender.sent.Message)
	}
	if diff := cmp.Diff(connID.String(), meta.ConnectionUuid); diff != "" {
		t.Errorf("ConnectionUuid mismatch (-want +got):\n%s", diff)
	}
	if meta.Hostname == "" {
		t.Error("expected non-empty hostname")
	}
	if meta.MaxConcurrentRequests != 10 {
		t.Errorf("MaxConcurrentRequests = %d, want 10", meta.MaxConcurrentRequests)
	}
}

func TestHandleMessage_ConnectionRequest_ReturnsErrorResponse(t *testing.T) {
	const reqID = "test-conn-req-id"

	sender := &mockSender{}
	cm := newTestConnectionManager()

	msg := &pb.ControllerMessage{
		RequestId: reqID,
		Message: &pb.ControllerMessage_ConnectionRequest{
			ConnectionRequest: &pb.ConnectionRequest{
				Action: pb.ConnectionRequest_ACTION_START_CLOSE,
			},
		},
	}

	if err := cm.handleMessage(context.Background(), sender, uuid.Nil, msg); err != nil {
		t.Fatalf("handleMessage() = %v", err)
	}

	if sender.sent == nil {
		t.Fatal("expected a message to be sent, got none")
	}
	if diff := cmp.Diff(reqID, sender.sent.RequestId); diff != "" {
		t.Errorf("request_id mismatch (-want +got):\n%s", diff)
	}
	errResp := sender.sent.GetErrorResponse()
	if errResp == nil {
		t.Fatalf("expected ErrorResponse, got %T", sender.sent.Message)
	}
	if errResp.Code == "" {
		t.Error("expected non-empty error code")
	}
}

func TestHandleMessage_UnknownMessage_ReturnsErrorResponse(t *testing.T) {
	const reqID = "test-unknown-msg-id"

	sender := &mockSender{}
	cm := newTestConnectionManager()

	// A ControllerMessage with no message field set triggers the default case.
	msg := &pb.ControllerMessage{RequestId: reqID}

	if err := cm.handleMessage(context.Background(), sender, uuid.Nil, msg); err != nil {
		t.Fatalf("handleMessage() = %v", err)
	}

	if sender.sent == nil {
		t.Fatal("expected a message to be sent, got none")
	}
	if diff := cmp.Diff(reqID, sender.sent.RequestId); diff != "" {
		t.Errorf("request_id mismatch (-want +got):\n%s", diff)
	}
	errResp := sender.sent.GetErrorResponse()
	if errResp == nil {
		t.Fatalf("expected ErrorResponse, got %T", sender.sent.Message)
	}
	if errResp.Code == "" {
		t.Error("expected non-empty error code")
	}
}
