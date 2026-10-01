package rawtunnel

import (
	"encoding/binary"
	"errors"
	"io"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

var (
	errHalfClose      = errors.New("rawtunnel: half close")
	errRecordTooLarge = errors.New("rawtunnel: record too large")
)

// closeMark is a length that cannot be a payload. The next four bytes are a
// RawCloseReason. A zero length is a half-close, which leaves the other
// direction open.
const closeMark = ^uint32(0)

type closeError struct {
	reason pb.RawCloseReason
}

func (e *closeError) Error() string {
	return "rawtunnel: closed " + e.reason.String()
}

// recordReader yields payload bytes. A zero-length record ends the current
// Read with errHalfClose so the caller can keep reading for a later reset.
type recordReader struct {
	r    io.Reader
	buf  []byte
	off  int
	half bool
}

func (r *recordReader) Read(p []byte) (int, error) {
	if r.off >= len(r.buf) {
		if r.half {
			return 0, errHalfClose
		}
		payload, err := readFrame(r.r)
		if err != nil {
			if errors.Is(err, errHalfClose) {
				r.half = true
			}
			return 0, err
		}
		r.buf = payload
		r.off = 0
	}
	n := copy(p, r.buf[r.off:])
	r.off += n
	if r.off >= len(r.buf) {
		r.buf = nil
	}
	return n, nil
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	switch {
	case n == 0:
		return nil, errHalfClose
	case n == closeMark:
		var raw [4]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return nil, err
		}
		return nil, &closeError{reason: pb.RawCloseReason(binary.BigEndian.Uint32(raw[:]))}
	case n > maxRecord:
		return nil, errRecordTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// readRecord returns one control payload. A half-close or close mark is not a
// drain.
func readRecord(r io.Reader) ([]byte, error) {
	payload, err := readFrame(r)
	if err != nil {
		var closed *closeError
		if errors.Is(err, errHalfClose) || errors.As(err, &closed) {
			return nil, errRecordTooLarge
		}
		return nil, err
	}
	return payload, nil
}

type recordWriter struct {
	w     io.Writer
	flush func()
}

func (w recordWriter) Write(p []byte) (int, error) {
	sent := 0
	for len(p) > 0 {
		n := min(len(p), maxRecord)
		if err := w.frame(p[:n]); err != nil {
			return sent, err
		}
		sent += n
		p = p[n:]
	}
	return sent, nil
}

func (w recordWriter) CloseWrite() error { return w.frame(nil) }

func (w recordWriter) frame(p []byte) error {
	// One Write so a close record on the same pipe cannot land between the
	// length and the payload. io.Pipe keeps each Write contiguous.
	buf := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(p)))
	copy(buf[4:], p)
	if _, err := w.w.Write(buf); err != nil {
		return err
	}
	if w.flush != nil {
		w.flush()
	}
	return nil
}

func (w recordWriter) frameClose(reason pb.RawCloseReason) error {
	var buf [8]byte
	binary.BigEndian.PutUint32(buf[0:4], closeMark)
	binary.BigEndian.PutUint32(buf[4:8], uint32(reason))
	if _, err := w.w.Write(buf[:]); err != nil {
		return err
	}
	if w.flush != nil {
		w.flush()
	}
	return nil
}
