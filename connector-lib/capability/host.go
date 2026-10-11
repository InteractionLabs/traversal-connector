package capability

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Canonical returns the one spelling of host that capabilities carry: an IP
// literal in its shortest form, or a lowercase ASCII name without a trailing
// dot. It refuses names a resolver could read as an address ("127.1").
func Canonical(host string) (string, bool) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap().String(), a.Zone() == ""
	}
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "" || len(h) > 253 {
		return "", false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 ||
			strings.Trim(l, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			return "", false
		}
	}
	if strings.Trim(strings.TrimPrefix(labels[len(labels)-1], "0x"), "0123456789abcdef") == "" {
		return "", false
	}
	return h, true
}

// IsCanonical reports whether host is already canonical.
func IsCanonical(host string) bool {
	c, ok := Canonical(host)
	return ok && c == host
}

// SplitAuthority parses a canonical host:port.
func SplitAuthority(authority string) (string, uint16, bool) {
	host, p, err := net.SplitHostPort(authority)
	if err != nil || !IsCanonical(host) {
		return "", 0, false
	}
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != p ||
		net.JoinHostPort(host, p) != authority {
		return "", 0, false
	}
	return host, uint16(port), true
}

// Absolute is host as a resolver must get it: names gain a trailing dot so a
// search list cannot rewrite them.
func Absolute(host string) string {
	if _, err := netip.ParseAddr(host); err == nil {
		return host
	}
	return host + "."
}
