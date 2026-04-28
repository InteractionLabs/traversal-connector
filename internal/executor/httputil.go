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
