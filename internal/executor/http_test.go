package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/internal/config"
)

func newTestExecutor(t *testing.T, timeout time.Duration, maxBodyMB int64) *Executor {
	t.Helper()
	cfg := &config.Config{
		RequestTimeout:       timeout,
		MaxRequestBodySizeMB: maxBodyMB,
	}
	exec, err := NewExecutor(cfg)
	if err != nil {
		t.Fatalf("NewExecutor() failed: %v", err)
	}
	return exec
}

func TestExecute_SuccessfulGET(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("expected Accept header, got %s", r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	exec := newTestExecutor(t, 5*time.Second, 32)

	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    server.URL + "/health",
		Headers: []*pb.Header{
			{Key: "Accept", Value: "application/json"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff(int32(http.StatusOK), resp.HttpStatus); diff != "" {
		t.Errorf("status mismatch (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(`{"status":"ok"}`, string(resp.Body)); diff != "" {
		t.Errorf("body mismatch (-want +got):\n%s", diff)
	}
}

func TestExecute_SuccessfulPOST(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"123"}`))
	}))
	defer server.Close()

	exec := newTestExecutor(t, 5*time.Second, 32)

	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "POST",
		Url:    server.URL + "/users",
		Headers: []*pb.Header{
			{Key: "Content-Type", Value: "application/json"},
		},
		Body: []byte(`{"name":"test"}`),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff(int32(http.StatusCreated), resp.HttpStatus); diff != "" {
		t.Errorf("status mismatch (-want +got):\n%s", diff)
	}
}

func TestExecute_InvalidURL(t *testing.T) {
	exec := newTestExecutor(t, 5*time.Second, 32)

	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    "ftp://invalid-scheme.com",
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if resp != nil {
		t.Errorf("expected nil response, got %v", resp)
	}
}

func TestExecute_EmptyURL(t *testing.T) {
	exec := newTestExecutor(t, 5*time.Second, 32)

	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    "",
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if resp != nil {
		t.Errorf("expected nil response, got %v", resp)
	}
}

func TestExecute_BodySizeLimitExceeded(t *testing.T) {
	exec := newTestExecutor(t, 5*time.Second, 1) // 1 MB limit

	// Create a body that exceeds 1 MB.
	largeBody := make([]byte, 1024*1024+1)

	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "POST",
		Url:    "https://example.com/upload",
		Body:   largeBody,
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("expected body size error message, got: %s", err)
	}

	if resp != nil {
		t.Errorf("expected nil response, got %v", resp)
	}
}

func TestExecute_BodyWithinLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exec := newTestExecutor(t, 5*time.Second, 1) // 1 MB limit

	// Create a body exactly at the limit.
	body := make([]byte, 1024*1024)

	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "POST",
		Url:    server.URL + "/upload",
		Body:   body,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff(int32(http.StatusOK), resp.HttpStatus); diff != "" {
		t.Errorf("status mismatch (-want +got):\n%s", diff)
	}
}

func TestExecute_NetworkError(t *testing.T) {
	exec := newTestExecutor(t, 2*time.Second, 32)

	// Use a URL that will fail to connect (closed server).
	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    "http://127.0.0.1:1",
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if resp != nil {
		t.Errorf("expected nil response, got %v", resp)
	}
}

func TestExecute_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Delay longer than the executor timeout.
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exec := newTestExecutor(t, 100*time.Millisecond, 32)

	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    server.URL + "/slow",
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if resp != nil {
		t.Errorf("expected nil response, got %v", resp)
	}
}

func TestExecute_HopByHopHeadersFiltered(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify hop-by-hop headers were stripped.
		if r.Header.Get("Connection") != "" {
			t.Errorf("Connection header should be filtered, got %s", r.Header.Get("Connection"))
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept header should be preserved, got %s", r.Header.Get("Accept"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exec := newTestExecutor(t, 5*time.Second, 32)

	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    server.URL,
		Headers: []*pb.Header{
			{Key: "Accept", Value: "application/json"},
			{Key: "Connection", Value: "keep-alive"},
			{Key: "Transfer-Encoding", Value: "chunked"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff(int32(http.StatusOK), resp.HttpStatus); diff != "" {
		t.Errorf("status mismatch (-want +got):\n%s", diff)
	}
}

func TestExecute_UpstreamErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal"}`))
	}))
	defer server.Close()

	exec := newTestExecutor(t, 5*time.Second, 32)

	// Even 5xx responses should come back as HttpResponse (not error),
	// per the design doc: "status, headers, body (even if status is 4xx/5xx)".
	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    server.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff(int32(http.StatusInternalServerError), resp.HttpStatus); diff != "" {
		t.Errorf("status mismatch (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(`{"error":"internal"}`, string(resp.Body)); diff != "" {
		t.Errorf("body mismatch (-want +got):\n%s", diff)
	}
}

func TestExecute_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exec := newTestExecutor(t, 5*time.Second, 32)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	resp, err := exec.Execute(ctx, &pb.HttpRequest{
		Method: "GET",
		Url:    server.URL,
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if resp != nil {
		t.Errorf("expected nil response, got %v", resp)
	}
}
