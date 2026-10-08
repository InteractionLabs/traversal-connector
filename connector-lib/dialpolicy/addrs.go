package dialpolicy

import (
	"errors"
	"net"
	"net/netip"
	"strings"
)

// builtinForbidden are ranges no raw pipe may reach, wherever the connector
// runs. Private ranges are allowed: reaching them is what raw pipes are for.
var builtinForbidden = []netip.Prefix{
	// "This network"; 0.0.0.0 reaches the local host.
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	// Link-local, including the metadata service at 169.254.169.254 on AWS,
	// GCP, Azure, and OCI, and ECS task credentials at 169.254.170.2.
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	// Reserved, including the limited broadcast address.
	netip.MustParsePrefix("240.0.0.0/4"),
	// Alibaba Cloud metadata.
	netip.MustParsePrefix("100.100.100.200/32"),
	// Azure WireServer.
	netip.MustParsePrefix("168.63.129.16/32"),
	// Oracle Cloud Classic metadata.
	netip.MustParsePrefix("192.0.0.192/32"),
	// Unspecified, loopback, and deprecated IPv4-compatible addresses.
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	// AWS's IPv6 link services: the metadata service at fd00:ec2::254 and EKS
	// Pod Identity credentials at fd00:ec2::23.
	netip.MustParsePrefix("fd00:ec2::/32"),
	// GCE metadata over IPv6.
	netip.MustParsePrefix("fd20:ce::254/128"),
}

// nat64Prefixes embed an IPv4 address in their last 32 bits. 64:ff9b::/96 is
// the well-known prefix; 64:ff9b:1::/48 is the local-use prefix. Either one
// reaches the IPv4 address a pipe would reach directly.
var nat64Prefixes = []netip.Prefix{
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
}

// forbiddenNames always reach the local host or a cloud metadata service,
// wherever they are resolved. They matter for proxied dials, where the proxy
// resolves the name and the connector never sees the address.
func forbiddenName(host string) bool {
	switch host {
	case "localhost", "ip6-localhost", "ip6-loopback",
		"metadata.google.internal", "metadata.goog",
		"instance-data.ec2.internal":
		return true
	default:
		return strings.HasSuffix(host, ".localhost")
	}
}

// interfacePrefixes returns a single-address prefix for each of the host's
// own addresses, so a pipe cannot reach services bound to the connector pod.
func interfacePrefixes() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var prefixes []netip.Prefix
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if addr, ok := netip.AddrFromSlice(ipNet.IP); ok {
			addr = addr.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return prefixes, nil
}

// normalizePrefix rejects an invalid prefix and rewrites an IPv4-mapped one
// into the IPv4 prefix it actually covers. forbidden compares unmapped
// addresses, so a mapped prefix would otherwise match nothing.
func normalizePrefix(prefix netip.Prefix) (netip.Prefix, error) {
	if !prefix.IsValid() {
		return netip.Prefix{}, errors.New("dialpolicy: invalid forbidden prefix")
	}
	// Check before masking: a mapped prefix shorter than /96 masks away the
	// 0xffff marker and would silently become a different range.
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, errors.New(
				"dialpolicy: an IPv4-mapped prefix must be at least /96")
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked(), nil
}

func (p *Policy) forbidden(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	for _, prefix := range nat64Prefixes {
		if !prefix.Contains(addr) {
			continue
		}
		embedded := addr.As16()
		if p.forbidden(netip.AddrFrom4([4]byte(embedded[12:]))) {
			return true
		}
	}
	for _, prefix := range p.deny {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
