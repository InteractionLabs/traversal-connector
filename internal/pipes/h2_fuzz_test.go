package pipes

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// FuzzH2Server feeds arbitrary frames after the client preface. The server
// must never panic or hang, whatever Envoy (or anything reaching the
// listener) sends.
func FuzzH2Server(f *testing.F) {
	var seed bytes.Buffer
	fr := http2.NewFramer(&seed, nil)
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, hf := range []hpack.HeaderField{{Name: ":method", Value: "CONNECT"}, {Name: ":authority", Value: "target:7001"}} {
		_ = enc.WriteField(hf)
	}
	_ = fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
	_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hb.Bytes(), EndHeaders: true})
	_ = fr.WriteData(1, false, []byte("hello"))
	_ = fr.WriteWindowUpdate(1, 1<<31-1)
	_ = fr.WriteWindowUpdate(0, 1<<31-1)
	_ = fr.WriteData(1, true, []byte("bye"))
	_ = fr.WriteRSTStream(1, http2.ErrCodeCancel)
	_ = fr.WritePing(false, [8]byte{1})
	_ = fr.WriteData(3, true, []byte("unknown stream"))
	f.Add(seed.Bytes())
	f.Add([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, frames []byte) {
		client, server := net.Pipe()
		s := &h2server{handle: func(st *h2stream) {
			_ = st.respond("200", nil, false)
			_, _ = io.CopyN(io.Discard, st, 1<<20)
			_, _ = st.Write([]byte("reply"))
			_ = st.CloseWrite()
		}}
		done := make(chan struct{})
		go func() { s.serveConn(server); close(done) }()
		go func() { _, _ = io.Copy(io.Discard, client) }()
		_ = client.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = client.Write([]byte(http2.ClientPreface))
		_, _ = client.Write(frames)
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("server did not finish after the client closed")
		}
		handlers := make(chan struct{})
		go func() { s.wg.Wait(); close(handlers) }()
		select {
		case <-handlers:
		case <-time.After(5 * time.Second):
			t.Fatal("a stream handler hung after the connection closed")
		}
	})
}
