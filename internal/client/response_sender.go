package client

import (
	"context"
	"errors"
	"log/slog"
	"time"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
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
			if err := ss.sender.Send(item.msg); err != nil {
				slog.ErrorContext(ctx, "response sender: stream send failed",
					"request_id", item.msg.RequestId,
					"error", err)
			}
		case <-ctx.Done():
			return
		case <-ss.done:
			return
		}
	}
}

func (ss *responseSender) close() {
	close(ss.done)
}
