package executor

import "net/url"

// hostFromURL extracts the host (hostname or hostname:port) from a raw
// URL string. It is intended for use as a low-cardinality metric
// attribute. Returns "unknown" if the URL cannot be parsed or has no
// host component.
func hostFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return "unknown"
	}
	return parsed.Host
}

// hostnameFromURL extracts just the hostname (no port, IPv6 brackets stripped)
// from a raw URL string. It is used to match redaction rule host allowlists.
// Returns "" if the URL cannot be parsed or has no host component.
func hostnameFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
