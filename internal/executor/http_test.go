package executor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/internal/config"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
)

func assertKind(t *testing.T, err error, want ErrorKind) {
	t.Helper()
	var ue *UpstreamError
	if !errors.As(err, &ue) {
		t.Fatalf("expected *UpstreamError, got %T: %v", err, err)
	}
	if ue.Kind != want {
		t.Errorf("kind mismatch: want %d got %d (err=%v)", want, ue.Kind, err)
	}
}

func findHeader(headers []*pb.Header, key string) (string, bool) {
	for _, h := range headers {
		if strings.EqualFold(h.Key, key) {
			return h.Value, true
		}
	}
	return "", false
}

func newTestExecutor(t *testing.T, timeout time.Duration, maxBodyMB int64) *Executor {
	t.Helper()
	cfg := &config.Config{
		RequestTimeout:       timeout,
		MaxRequestBodySizeMB: maxBodyMB,
	}
	exec, err := NewExecutor(cfg, redact.NewRedactor())
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
	assertKind(t, err, KindInvalidRequest)

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
	assertKind(t, err, KindInvalidRequest)

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
	assertKind(t, err, KindRequestTooLarge)

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
	assertKind(t, err, KindUpstreamUnavailable)

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
	assertKind(t, err, KindUpstreamTimeout)

	if resp != nil {
		t.Errorf("expected nil response, got %v", resp)
	}
}

// TestExecute_UpstreamAborted exercises the case where the upstream sends
// response headers but closes the connection mid-body. This is the canonical
// "broken pipe / aborted stream" condition that should surface as
// KindUpstreamAborted (HTTP 502 at the controller).
func TestExecute_UpstreamAborted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Promise more bytes than we'll send, then drop the connection.
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("ResponseWriter is not a Hijacker")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack failed: %v", err)
		}
		_ = conn.Close()
	}))
	defer server.Close()

	exec := newTestExecutor(t, 5*time.Second, 32)

	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    server.URL,
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	assertKind(t, err, KindUpstreamAborted)

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

func TestExecute_ContentLengthRewrittenAfterRedaction(t *testing.T) {
	body := []byte("contact user@example.com for help")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer server.Close()

	redactor := redact.NewRedactor()
	if err := redactor.Update(&redact.RulesFile{
		Version: "v1",
		Rules: []redact.Rule{
			{
				Name:        "email",
				Type:        "regex",
				Pattern:     `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
				Replacement: "[REDACTED]",
			},
		},
	}); err != nil {
		t.Fatalf("redactor.Update() error: %v", err)
	}

	cfg := &config.Config{RequestTimeout: 5 * time.Second, MaxRequestBodySizeMB: 32}
	exec, err := NewExecutor(cfg, redactor)
	if err != nil {
		t.Fatalf("NewExecutor() failed: %v", err)
	}

	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    server.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantBody := "contact [REDACTED] for help"
	if diff := cmp.Diff(wantBody, string(resp.Body)); diff != "" {
		t.Errorf("body mismatch (-want +got):\n%s", diff)
	}

	got, ok := findHeader(resp.Headers, "Content-Length")
	if !ok {
		t.Fatal("Content-Length header missing from response")
	}
	if diff := cmp.Diff(strconv.Itoa(len(wantBody)), got); diff != "" {
		t.Errorf("Content-Length mismatch (-want +got):\n%s", diff)
	}
}

func TestExecute_ContentLengthNotAddedWhenAbsent(t *testing.T) {
	// When the handler doesn't set Content-Length and writes via chunked
	// encoding, the Go client strips Content-Length from resp.Header. We
	// must not synthesize one after redaction.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		// Force chunked by flushing before the full body is known.
		_, _ = w.Write([]byte("contact user@example.com"))
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte(" for help"))
	}))
	defer server.Close()

	redactor := redact.NewRedactor()
	if err := redactor.Update(&redact.RulesFile{
		Version: "v1",
		Rules: []redact.Rule{
			{
				Name:        "email",
				Type:        "regex",
				Pattern:     `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
				Replacement: "[REDACTED]",
			},
		},
	}); err != nil {
		t.Fatalf("redactor.Update() error: %v", err)
	}

	cfg := &config.Config{RequestTimeout: 5 * time.Second, MaxRequestBodySizeMB: 32}
	exec, err := NewExecutor(cfg, redactor)
	if err != nil {
		t.Fatalf("NewExecutor() failed: %v", err)
	}

	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    server.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := findHeader(resp.Headers, "Content-Length"); ok {
		t.Error("Content-Length should not be set when upstream did not send one")
	}
}

func TestExecute_JSONResponse_StructuredRedactionRespectsFieldFilters(t *testing.T) {
	const upstream = `{"message":"contact a@b.com","safe":"contact c@d.com"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstream))
	}))
	defer server.Close()

	redactor := redact.NewRedactor()
	if err := redactor.Update(&redact.RulesFile{
		Rules: []redact.Rule{{
			Name:         "email",
			Type:         "regex-structured-data",
			Pattern:      `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			Replacement:  "[EMAIL]",
			RedactFields: []string{"message"}, // only redact "message", not "safe"
		}},
	}); err != nil {
		t.Fatalf("redactor.Update() error: %v", err)
	}

	cfg := &config.Config{RequestTimeout: 5 * time.Second, MaxRequestBodySizeMB: 32}
	exec, err := NewExecutor(cfg, redactor)
	if err != nil {
		t.Fatalf("NewExecutor() failed: %v", err)
	}

	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    server.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body := string(resp.Body)
	if !strings.Contains(body, `"message":"contact [EMAIL]"`) {
		t.Errorf("expected message to be redacted, got %q", body)
	}
	if !strings.Contains(body, `"safe":"contact c@d.com"`) {
		t.Errorf("expected safe to be unchanged, got %q", body)
	}
}

func TestExecute_NonJSONContentType_StructuredRuleSkipped_LegacyFires(t *testing.T) {
	// On non-JSON bodies, structured rules are skipped (their field filters
	// can't be honored on raw bytes), but legacy regex rules still fire.
	const upstream = "email a@b.com ssn 123-45-6789"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstream))
	}))
	defer server.Close()

	redactor := redact.NewRedactor()
	if err := redactor.Update(&redact.RulesFile{
		Rules: []redact.Rule{
			{
				Name:         "email",
				Type:         "regex-structured-data",
				Pattern:      `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
				Replacement:  "[EMAIL]",
				RedactFields: []string{"some-field"},
			},
			{
				Name:        "ssn",
				Type:        "regex",
				Pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
				Replacement: "[SSN]",
			},
		},
	}); err != nil {
		t.Fatalf("redactor.Update() error: %v", err)
	}

	cfg := &config.Config{RequestTimeout: 5 * time.Second, MaxRequestBodySizeMB: 32}
	exec, err := NewExecutor(cfg, redactor)
	if err != nil {
		t.Fatalf("NewExecutor() failed: %v", err)
	}

	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    server.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(resp.Body) != "email a@b.com ssn [SSN]" {
		t.Errorf(
			"structured rule should be skipped, legacy ssn should fire; got %q",
			string(resp.Body),
		)
	}
}

func TestExecute_JSONContentTypeButInvalidBody_StructuredSkipped_LegacyFires(t *testing.T) {
	// Invalid JSON: per-field redaction can't run, structured rules are
	// skipped. Legacy regex rules still fire byte-level.
	const upstream = "not json a@b.com 123-45-6789"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstream))
	}))
	defer server.Close()

	redactor := redact.NewRedactor()
	if err := redactor.Update(&redact.RulesFile{
		Rules: []redact.Rule{
			{
				Name:        "email",
				Type:        "regex-structured-data",
				Pattern:     `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
				Replacement: "[EMAIL]",
			},
			{
				Name:        "ssn",
				Type:        "regex",
				Pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
				Replacement: "[SSN]",
			},
		},
	}); err != nil {
		t.Fatalf("redactor.Update() error: %v", err)
	}

	cfg := &config.Config{RequestTimeout: 5 * time.Second, MaxRequestBodySizeMB: 32}
	exec, err := NewExecutor(cfg, redactor)
	if err != nil {
		t.Fatalf("NewExecutor() failed: %v", err)
	}

	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    server.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(resp.Body) != "not json a@b.com [SSN]" {
		t.Errorf(
			"structured rule should be skipped, legacy ssn should fire; got %q",
			string(resp.Body),
		)
	}
}

func TestExecute_JSONResponse_LegacyRulesAlsoFire(t *testing.T) {
	// On JSON bodies, structured rules fire per-field AND legacy regex rules
	// fire byte-level over the result.
	const upstream = `{"key":"a@b.com","ss":"123-45-6789","not-key":"c@d.com"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(upstream))
	}))
	defer server.Close()

	redactor := redact.NewRedactor()
	if err := redactor.Update(&redact.RulesFile{
		Rules: []redact.Rule{
			{
				Name:         "email",
				Type:         "regex-structured-data",
				Pattern:      `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
				Replacement:  "[EMAIL]",
				RedactFields: []string{"key"}, // only the "key" field
			},
			{
				Name:        "ssn",
				Type:        "regex",
				Pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
				Replacement: "[SSN]",
			},
		},
	}); err != nil {
		t.Fatalf("redactor.Update() error: %v", err)
	}

	cfg := &config.Config{RequestTimeout: 5 * time.Second, MaxRequestBodySizeMB: 32}
	exec, err := NewExecutor(cfg, redactor)
	if err != nil {
		t.Fatalf("NewExecutor() failed: %v", err)
	}

	resp, err := exec.Execute(context.Background(), &pb.HttpRequest{
		Method: "GET",
		Url:    server.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body := string(resp.Body)
	if !strings.Contains(body, `"key":"[EMAIL]"`) {
		t.Errorf("key should be redacted by structured rule; got %q", body)
	}
	if !strings.Contains(body, `"not-key":"c@d.com"`) {
		t.Errorf("not-key should NOT be redacted (filter excludes it); got %q", body)
	}
	if !strings.Contains(body, `"ss":"[SSN]"`) {
		t.Errorf("ssn should be redacted byte-level by legacy rule; got %q", body)
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
	assertKind(t, err, KindClientCanceled)

	if resp != nil {
		t.Errorf("expected nil response, got %v", resp)
	}
}
