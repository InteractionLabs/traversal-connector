package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/connector"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

// sendItem wraps a ConnectorMessage with the time it was enqueued so we can
// measure how long it waits in the send buffer before being written.
type sendItem struct {
	msg        *pb.ConnectorMessage
	enqueuedAt time.Time
}

// responseSender wraps a streamSender with a channel-based send queue
// so that multiple goroutines can send messages concurrently without
// racing on the underlying gRPC stream.
type responseSender struct {
	sender  streamSender
	sendCh  chan *sendItem
	done    chan struct{}
	metrics *connectionMetrics
}

// newResponseSender creates a new response sender wrapping the given stream.
// bufferSize controls the send channel capacity; use 2× the max concurrent
// requests so bursts rarely block. Call run() in a goroutine to start
// processing, and close() when done.
func newResponseSender(
	sender streamSender,
	bufferSize int,
	metrics *connectionMetrics,
) *responseSender {
	return &responseSender{
		sender:  sender,
		sendCh:  make(chan *sendItem, bufferSize),
		done:    make(chan struct{}),
		metrics: metrics,
	}
}

// Send enqueues a message for serialized delivery. It blocks if the send
// buffer is full and returns an error if the sender has been shut down.
func (ss *responseSender) Send(msg *pb.ConnectorMessage) error {
	item := &sendItem{msg: msg, enqueuedAt: time.Now()}
	select {
	case ss.sendCh <- item:
		return nil
	case <-ss.done:
		return errors.New("response sender closed")
	}
}

// run processes the send queue until the context is canceled or close() is called.
func (ss *responseSender) run(ctx context.Context) {
	for {
		select {
		case item := <-ss.sendCh:
			if ss.metrics != nil {
				waitMs := float64(time.Since(item.enqueuedAt).Milliseconds())
				ss.metrics.responseSendWaitLatency.Record(ctx, waitMs)
			}
			ss.send(ctx, item.msg)
		case <-ctx.Done():
			return
		case <-ss.done:
			return
		}
	}
}

// send writes msg to the stream. If an HTTP response cannot be written, it
// makes one attempt to send an UPSTREAM_ERROR for the same request instead:
// the controller holds the request open until something arrives for its ID,
// so a silently dropped response costs the caller a full timeout. A failed
// fallback is only logged; it is never retried or itself replaced.
func (ss *responseSender) send(ctx context.Context, msg *pb.ConnectorMessage) {
	err := ss.sender.Send(msg)
	if err == nil {
		return
	}
	safeErr := telemetry.SanitizeError(err)
	slog.ErrorContext(ctx, "response sender: stream send failed",
		"request_id", msg.RequestId,
		"error", safeErr)

	if msg.GetHttpResponse() == nil {
		return
	}
	fallback := &pb.ConnectorMessage{
		RequestId: msg.RequestId,
		Message: &pb.ConnectorMessage_ErrorResponse{
			ErrorResponse: &pb.ErrorResponse{
				Code: string(connector.ErrorCodeUpstreamError),
				Message: fmt.Sprintf(
					"connector failed to send upstream response: %s", safeErr,
				),
			},
		},
	}
	if err := ss.sender.Send(fallback); err != nil {
		slog.ErrorContext(ctx, "response sender: fallback error response send failed",
			"request_id", msg.RequestId,
			"error", telemetry.SanitizeError(err))
	}
}

func (ss *responseSender) close() {
	close(ss.done)
}
