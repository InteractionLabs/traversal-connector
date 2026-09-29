package rawtunnel

import (
	"encoding/binary"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

// encodeFrames lays frames out as the fuzz input format: each frame's wire
// encoding preceded by its 16-bit big-endian length. The first byte selects
// the role.
func encodeFrames(role byte, frames ...*pb.RawTunnelFrame) []byte {
	out := []byte{role}
	for _, f := range frames {
		b, err := proto.Marshal(f)
		if err != nil || len(b) > 0xffff {
			panic("unencodable seed frame")
		}
		out = binary.BigEndian.AppendUint16(out, uint16(len(b))) //nolint:gosec // checked above.
		out = append(out, b...)
	}
	return out
}

// FuzzPeerFrames feeds arbitrary frame sequences to a Mux in either role. It
// must never panic, and once the tunnel ends every pipe must be released and
// every Local closed.
func FuzzPeerFrames(f *testing.F) {
	f.Add(encodeFrames(0, open(1), data(1, 10), window(1, 100), halfClose(1),
		reset(1, cancelled), open(2), ping(1, false), drain(1)))
	f.Add(encodeFrames(0, open(1), fill(Window)[0], open(2), open(1), data(3, 1)))
	f.Add(encodeFrames(0, open(3), reset(3, 0), open(4), data(4, 0), halfClose(4),
		halfClose(4)))
	f.Add(encodeFrames(1, opened(1), data(1, 5), halfClose(1),
		closeFrame(1, pb.RawCloseReason_RAW_CLOSE_REASON_COMPLETED), opened(2),
		openError(3, pb.RawOpenFailureReason_RAW_OPEN_FAILURE_REASON_CAPACITY, "x")))
	f.Add(encodeFrames(1, reset(2, cancelled), closeFrame(2, cancelled), opened(3),
		window(3, 7), ping(5, true), drain(2), opened(9)))

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) == 0 {
			return
		}
		role := RoleConnector
		if input[0]%2 == 1 {
			role = RoleController
		}
		frames := decodeFrames(input[1:])

		ours, theirs := streamPair(len(frames) + 8)
		cfg := Config{Role: role, MaxPipes: 3, IdleTimeout: time.Minute}
		var locals []*memLocal
		localCh := make(chan *memLocal, 64)
		if role == RoleConnector {
			cfg.Accept = func(p *Pipe, _ *pb.RawOpen) {
				l := newMemLocal(true)
				localCh <- l
				_ = p.Start(l)
			}
		}
		cfg.Abort = theirs.abort
		m, err := New(cfg, theirs)
		if err != nil {
			t.Fatal(err)
		}
		runErr := make(chan error, 1)
		go func() { runErr <- m.Run(t.Context()) }()
		go func() {
			for {
				if _, err := ours.Receive(); err != nil {
					return
				}
			}
		}()
		if role == RoleController {
			for range 3 {
				p, err := m.Open(testCapability, "db.internal", 5432, passthrough)
				if err != nil {
					t.Fatal(err)
				}
				l := newMemLocal(true)
				locals = append(locals, l)
				go func() {
					if p.WaitOpened(t.Context()) == nil {
						_ = p.Start(l)
					} else {
						_ = l.Close()
					}
				}()
			}
		}
		for _, fr := range frames {
			if ours.Send(fr) != nil {
				break
			}
		}
		time.Sleep(time.Millisecond)
		ours.close()
		select {
		case <-runErr:
		case <-time.After(waitTimeout):
			t.Fatal("Run did not return after the stream ended")
		}
		deadline := time.Now().Add(waitTimeout)
		for slots(m) != 0 {
			if time.Now().After(deadline) {
				t.Fatalf("%d pipes still hold slots", slots(m))
			}
			time.Sleep(time.Millisecond)
		}
		for len(localCh) > 0 {
			locals = append(locals, <-localCh)
		}
		for _, l := range locals {
			l.waitClosed(t)
		}
	})
}

func decodeFrames(b []byte) []*pb.RawTunnelFrame {
	var frames []*pb.RawTunnelFrame
	for len(b) >= 2 && len(frames) < 256 {
		n := int(b[0])<<8 | int(b[1])
		b = b[2:]
		if n > len(b) {
			break
		}
		f := new(pb.RawTunnelFrame)
		if proto.Unmarshal(b[:n], f) == nil {
			frames = append(frames, f)
		}
		b = b[n:]
	}
	return frames
}
