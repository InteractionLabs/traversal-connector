package rawpipe_test

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
)

func TestRefuse(t *testing.T) {
	for _, reason := range []rawpipe.Reason{rawpipe.WrongDestination, rawpipe.UpstreamFailed} {
		w := httptest.NewRecorder()
		rawpipe.Refuse(w, reason, "why")
		if w.Code != reason.Status() || w.Header().Get(rawpipe.HeaderReason) != string(reason) ||
			w.Body.String() != "why\n" {
			t.Errorf("%s: %d %q %q", reason, w.Code, w.Header().Get(rawpipe.HeaderReason), w.Body)
		}
	}
}

// TestAuthority: one spelling per destination, the port from the scheme
// when absent.
func TestAuthority(t *testing.T) {
	type want struct {
		host string
		port uint16
	}
	for raw, w := range map[string]*want{
		"http://api.internal/x":     {"api.internal", 80},
		"https://API.Internal./x":   {"api.internal", 443},
		"https://api.internal:8443": {"api.internal", 8443},
		"http://[::ffff:10.0.0.1]/": {"10.0.0.1", 80},
		"https://api.internal:/":    {"api.internal", 443},
		"ftp://api.internal/":       nil,
		"https://api.internal:0/":   nil,
		"https://api.internal:0443": nil,
		"https://127.1/":            nil,
		"https://[fe80::1%25en0]/":  nil,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		host, port, ok := rawpipe.Authority(u)
		switch {
		case w == nil && ok:
			t.Errorf("Authority(%q) = %s %d, want refused", raw, host, port)
		case w != nil && (!ok || host != w.host || port != w.port):
			t.Errorf("Authority(%q) = %s %d %v, want %s %d", raw, host, port, ok, w.host, w.port)
		}
	}
}
