package capability

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

const (
	maxHostBytes  = 253
	maxLabelBytes = 63
)

var errInvalidHost = errors.New("capability: invalid host")

// lookupProfile maps hostnames the way resolvers see them: case-folded,
// width-normalized, and IDNA 2008 A-labels, with underscores allowed because
// internal service names use them.
var lookupProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.StrictDomainName(false),
	idna.Transitional(false),
)

// CanonicalHost returns the one canonical spelling of a destination host, the
// form signers put in capabilities and validators compare exactly. A canonical
// hostname has no trailing dot, so it is a relative name: resolvers must be
// given AbsoluteHost, not the canonical form, or a search list can send the
// dial somewhere else. IP literals
// become their shortest standard text (IPv4-mapped IPv6 becomes IPv4);
// hostnames become lowercase ASCII without a trailing dot. It rejects anything
// a resolver or URL parser could read as a different destination: IPv6 zones,
// brackets, ports, empty or oversized labels, characters outside
// [a-z0-9_-], and names ending in a number that are not valid IPv4, such as
// "127.1" or "0x7f.1", which some resolvers treat as addresses.
func CanonicalHost(host string) (string, error) {
	if host == "" || len(host) > maxHostBytes+1 {
		return "", errInvalidHost
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return canonicalAddr(addr)
	}
	if !utf8.ValidString(host) || strings.ContainsAny(host, ":[]%") {
		return "", errInvalidHost
	}
	ascii, err := lookupProfile.ToASCII(host)
	if err != nil {
		return "", errInvalidHost
	}
	// Some inputs map to A-labels the profile itself rejects. Requiring a
	// fixed point keeps every canonical host canonical.
	if again, err := lookupProfile.ToASCII(ascii); err != nil || again != ascii {
		return "", errInvalidHost
	}
	ascii = strings.TrimSuffix(ascii, ".")
	if addr, err := netip.ParseAddr(ascii); err == nil {
		return canonicalAddr(addr)
	}
	if ascii == "" || len(ascii) > maxHostBytes {
		return "", errInvalidHost
	}
	labels := strings.Split(ascii, ".")
	for _, label := range labels {
		if !validLabel(label) {
			return "", errInvalidHost
		}
	}
	if endsInNumber(labels[len(labels)-1]) {
		return "", errInvalidHost
	}
	return ascii, nil
}

// CanonicalAuthority returns host:port with IPv6 hosts bracketed. host must
// already be canonical.
func CanonicalAuthority(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
}

// SplitAuthority parses a canonical host:port, the form CanonicalAuthority
// returns. The host must already be canonical and the port must be decimal
// 1-65535 without a sign or leading zeros, so the authority checked is the one
// dialed.
func SplitAuthority(authority string) (host string, port uint16, ok bool) {
	host, portText, err := net.SplitHostPort(authority)
	if err != nil {
		return "", 0, false
	}
	if canonical, err := CanonicalHost(host); err != nil || canonical != host {
		return "", 0, false
	}
	p, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || p == 0 || strconv.FormatUint(p, 10) != portText {
		return "", 0, false
	}
	return host, uint16(p), true
}

// AbsoluteHost returns host in the form a resolver must be given. Canonical
// hostnames are relative, so this adds a trailing dot and the lookup cannot be
// rewritten by a search list. IP literals are unchanged. host must already be
// canonical.
func AbsoluteHost(host string) string {
	if _, err := netip.ParseAddr(host); err == nil {
		return host
	}
	return host + "."
}

func canonicalAddr(addr netip.Addr) (string, error) {
	if addr.Zone() != "" {
		return "", errInvalidHost
	}
	return addr.Unmap().String(), nil
}

func validLabel(label string) bool {
	if label == "" || len(label) > maxLabelBytes {
		return false
	}
	for i := range len(label) {
		c := label[i]
		if ('a' > c || c > 'z') && ('0' > c || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// endsInNumber reports whether a final label is one the WHATWG URL host parser
// treats as numeric, which makes the whole name an IPv4 address to it.
func endsInNumber(label string) bool {
	if hex, ok := strings.CutPrefix(label, "0x"); ok {
		return strings.Trim(hex, "0123456789abcdef") == ""
	}
	return strings.Trim(label, "0123456789") == ""
}
