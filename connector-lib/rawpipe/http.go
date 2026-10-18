// What the connector and the Integration Proxy share about the HTTP inside a
// pipe: how a request names its destination, and how a refusal is answered.

package rawpipe

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/InteractionLabs/traversal-connector/connector-lib/internal/hostname"
)

// Refuse answers a request with reason: reason.Status(), HeaderReason, and
// msg as the body.
func Refuse(w http.ResponseWriter, reason Reason, msg string) {
	w.Header().Set(HeaderReason, string(reason))
	http.Error(w, msg, reason.Status())
}

// Authority is the destination u names, as a capability names it: the
// canonical host, and the port, which defaults from the scheme (http 80,
// https 443). It is not ok for a host that has no canonical form, or a port
// that is not a canonical decimal from 1 to 65535: a second spelling of a
// destination would be a second destination.
func Authority(u *url.URL) (host string, port uint16, ok bool) {
	host, ok = hostname.Canonical(u.Hostname())
	if !ok {
		return "", 0, false
	}
	switch p := u.Port(); {
	case p != "":
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != p {
			return "", 0, false
		}
		return host, uint16(n), true
	case u.Scheme == "http":
		return host, 80, true
	case u.Scheme == "https":
		return host, 443, true
	}
	return "", 0, false
}
