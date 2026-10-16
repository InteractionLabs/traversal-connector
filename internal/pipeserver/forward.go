package pipeserver

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
)

// forward sends one request from inside a pipe to the pipe's destination,
// or answers a probe. The request's authority, the port defaulting from its
// scheme, must be the pipe's: the capability is for that host:port only.
func (s *Server) forward(w http.ResponseWriter, r *http.Request, pipe *url.URL) {
	if r.Method == http.MethodConnect {
		rawpipe.Refuse(w, rawpipe.ProtocolError, "CONNECT is not carried inside a pipe")
		return
	}
	scheme, err := requestScheme(r)
	if err != nil {
		rawpipe.Refuse(w, rawpipe.ProtocolError, err.Error())
		return
	}
	r.Header.Del(rawpipe.HeaderUpstreamScheme)
	host, port, ok := rawpipe.Authority(&url.URL{Scheme: scheme, Host: r.Host})
	if !ok || net.JoinHostPort(host, strconv.Itoa(int(port))) != pipe.Host {
		rawpipe.Refuse(w, rawpipe.WrongDestination,
			"the request is not for this pipe's destination")
		return
	}
	if pipe.Host == rawpipe.ProbeAuthority {
		if r.URL.Path != rawpipe.ProbePath || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		s.Ready.ServeHTTP(w, r)
		return
	}
	s.Upstream.Forward(w, r, &url.URL{Scheme: scheme, Host: pipe.Host})
}

// requestScheme is the destination's scheme for r. On HTTP/2 it is
// rawpipe.HeaderUpstreamScheme, https when absent: net/http does not show a
// handler :scheme, and r.TLS is the pipe's own TLS, not the destination's.
// On HTTP/1.1 it is the absolute-form target's; origin form names no scheme,
// so it is refused rather than guessed.
func requestScheme(r *http.Request) (string, error) {
	if r.ProtoMajor == 2 {
		switch v := r.Header.Get(rawpipe.HeaderUpstreamScheme); v {
		case "":
			return "https", nil
		case "http", "https":
			return v, nil
		}
		return "", errors.New(rawpipe.HeaderUpstreamScheme + " is http or https")
	}
	if r.URL.Scheme == "http" || r.URL.Scheme == "https" {
		return r.URL.Scheme, nil
	}
	return "", errors.New(
		"HTTP/1.1 requests in a pipe are in absolute form (GET https://host/path)")
}
