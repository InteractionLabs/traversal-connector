package client

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/connector"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

// recordingSender records every message passed to Send and fails those the
// fail predicate selects.
type recordingSender struct {
	mu   sync.Mutex
	sent []*pb.ConnectorMessage
	fail func(*pb.ConnectorMessage) bool
}

func (r *recordingSender) Send(msg *pb.ConnectorMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, msg)
	if r.fail(msg) {
		return errors.New("write envelope: size out of bounds")
	}
	return nil
}

func (r *recordingSender) attempts() []*pb.ConnectorMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*pb.ConnectorMessage(nil), r.sent...)
}

// drainResponseSender enqueues msgs, runs the sender until every message and
// any follow-up has been attempted, and returns what reached the stream.
func drainResponseSender(
	t *testing.T,
	sender *recordingSender,
	wantAttempts int,
	msgs ...*pb.ConnectorMessage,
) []*pb.ConnectorMessage {
	t.Helper()
	ss := newResponseSender(sender, len(msgs), nil)
	for _, msg := range msgs {
		if err := ss.Send(msg); err != nil {
			t.Fatalf("Send() error: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ss.run(ctx)
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for len(sender.attempts()) < wantAttempts && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	// Leave time for any unexpected extra attempt to show up.
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	return sender.attempts()
}

func httpResponseMessage(requestID string) *pb.ConnectorMessage {
	return &pb.ConnectorMessage{
		RequestId: requestID,
		Message: &pb.ConnectorMessage_HttpResponse{
			HttpResponse: &pb.HttpResponse{HttpStatus: 200, Body: []byte("body")},
		},
	}
}

func TestResponseSender_FailedHTTPResponseSendsOneErrorResponse(t *testing.T) {
	const reqID = "req-failed-response"
	sender := &recordingSender{fail: func(msg *pb.ConnectorMessage) bool {
		return msg.GetHttpResponse() != nil
	}}

	got := drainResponseSender(t, sender, 2, httpResponseMessage(reqID))

	if len(got) != 2 {
		t.Fatalf("Send() attempts = %d, want 2 (response, then error): %v", len(got), got)
	}
	errResp := got[1].GetErrorResponse()
	if errResp == nil {
		t.Fatalf("follow-up message = %T, want ErrorResponse", got[1].Message)
	}
	if got[1].RequestId != reqID {
		t.Errorf("follow-up request_id = %q, want %q", got[1].RequestId, reqID)
	}
	if errResp.Code != string(connector.ErrorCodeUpstreamError) {
		t.Errorf("follow-up code = %q, want %q", errResp.Code, connector.ErrorCodeUpstreamError)
	}
	if errResp.Message == "" {
		t.Error("follow-up message is empty, want the send error")
	}
}

func TestResponseSender_FailedFallbackDoesNotRetry(t *testing.T) {
	sender := &recordingSender{fail: func(*pb.ConnectorMessage) bool { return true }}
	errMsg := &pb.ConnectorMessage{
		RequestId: "req-error",
		Message: &pb.ConnectorMessage_ErrorResponse{
			ErrorResponse: &pb.ErrorResponse{Code: "UPSTREAM_ERROR", Message: "boom"},
		},
	}

	got := drainResponseSender(t, sender, 3, httpResponseMessage("req-http"), errMsg)

	// One attempt for the response, one for its fallback, and one for the
	// queued ErrorResponse, which gets no fallback of its own.
	if len(got) != 3 {
		t.Fatalf("Send() attempts = %d, want 3: %v", len(got), got)
	}
	if got[0].GetHttpResponse() == nil || got[1].GetErrorResponse() == nil ||
		got[1].RequestId != "req-http" {
		t.Errorf("attempts = %v, want response then its fallback error", got)
	}
	if got[2] != errMsg {
		t.Errorf("third attempt = %v, want the queued ErrorResponse", got[2])
	}
}

func TestResponseSender_SuccessfulSendHasNoFollowUp(t *testing.T) {
	sender := &recordingSender{fail: func(*pb.ConnectorMessage) bool { return false }}

	got := drainResponseSender(t, sender, 1, httpResponseMessage("req-ok"))

	if len(got) != 1 || got[0].GetHttpResponse() == nil {
		t.Fatalf("attempts = %v, want exactly the HttpResponse", got)
	}
}
