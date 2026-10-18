// Package hostname is the canonical spelling of a host, shared by capability
// (the host a capability names) and rawpipe (the host a request in a pipe
// names), which capability imports.
package hostname

import (
	"net/netip"
	"strings"
)

// Canonical is capability.Canonical, which documents it. It lives here so
// rawpipe, which capability imports, can use it too.
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
	if numeric(labels[len(labels)-1]) {
		return "", false
	}
	return h, true
}

// numeric reports a last label the WHATWG URL parser reads as an IPv4 part,
// so the whole name would be taken as an address: all decimal digits, or 0x
// followed by hex digits (possibly none). "de", "ca", "db" and "cafe" are
// names.
func numeric(label string) bool {
	if hex, ok := strings.CutPrefix(label, "0x"); ok {
		return strings.Trim(hex, "0123456789abcdef") == ""
	}
	return strings.Trim(label, "0123456789") == ""
}
