// Splice is the pipe copy the connector, the edge controller and the
// Integration Proxy share. It is not io.Copy or httputil.ReverseProxy because
// those cannot tell a clean end from a failure: here a clean end on one side
// becomes a half-close (CloseWrite) on the other, and a failure a reset
// (Abort). Splice also enforces idle and lifetime limits and counts bytes for
// the audit log.

package halfconn

import (
	"errors"
	"io"
	"sync"
	"time"
)

// End is one side of a pipe. Its Read returns io.EOF at a clean end.
type End interface {
	io.Reader
	io.Writer
	// CloseWrite ends the bytes toward this end cleanly.
	CloseWrite() error
	// Abort resets this end, so it sees a failure rather than an end, and
	// unblocks any Read or Write on it.
	Abort()
}

// Outcome is how a pipe ended.
type Outcome string

// Outcomes.
const (
	Completed     Outcome = "completed"
	Limit         Outcome = "limit"
	CallerAborted Outcome = "caller_aborted"
	DestAborted   Outcome = "destination_aborted"
)

// Limits end a pipe that is Lifetime old or has moved no bytes for Idle.
// Zero is no limit.
type Limits struct{ Lifetime, Idle time.Duration }

// Splice copies both ways until both directions end. A clean end on one side
// is a clean end on the other; the first failure, or a limit, aborts both
// ends, so neither mistakes it for an end. sent is caller to dest.
func Splice(caller, dest End, l Limits) (sent, received int64, outcome Outcome) {
	var once sync.Once
	outcome = Completed
	fail := func(o Outcome) {
		once.Do(func() { outcome = o; caller.Abort(); dest.Abort() })
	}
	limit := func() { fail(Limit) }
	touch := func() {}
	if l.Idle > 0 {
		idle := time.AfterFunc(l.Idle, limit)
		defer idle.Stop()
		touch = func() { idle.Reset(l.Idle) }
	}
	if l.Lifetime > 0 {
		defer time.AfterFunc(l.Lifetime, limit).Stop()
	}
	up := make(chan int64, 1)
	go func() { up <- copyEnd(dest, caller, touch, fail, CallerAborted, DestAborted) }()
	received = copyEnd(caller, dest, touch, fail, DestAborted, CallerAborted)
	sent = <-up
	// A limit firing now waits for this, or finds it done: outcome is settled.
	once.Do(func() {})
	return sent, received, outcome
}

const copyBuffer = 64 << 10

func copyEnd(dst, src End, touch func(), fail func(Outcome), srcFailed, dstFailed Outcome) int64 {
	buf := make([]byte, copyBuffer)
	var n int64
	for {
		r, err := src.Read(buf)
		if r > 0 {
			touch()
			if _, werr := dst.Write(buf[:r]); werr != nil {
				fail(dstFailed)
				return n
			}
			n += int64(r)
		}
		switch {
		case errors.Is(err, io.EOF):
			if dst.CloseWrite() != nil {
				fail(dstFailed)
			}
			return n
		case err != nil:
			fail(srcFailed)
			return n
		}
	}
}

// ConnEnd is c as a pipe End. Abort resets it.
func ConnEnd(c Conn) End { return connEnd{c} }

type connEnd struct{ Conn }

func (c connEnd) Abort() {
	if tcp, ok := c.Conn.(interface{ SetLinger(int) error }); ok {
		_ = tcp.SetLinger(0)
	}
	_ = c.Close()
}
