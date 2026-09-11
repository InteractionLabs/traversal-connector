package client

import (
	"math"

	"github.com/InteractionLabs/traversal-connector/internal/config"
)

const (
	bytesPerMB = 1024 * 1024

	// unlimitedMessageSize is how the transport spells "no ceiling".
	unlimitedMessageSize = 0

	// tunnelMessageOverheadBytes is the room a tunnel message needs beyond the
	// body it carries: the request id, the method, the target URL, the whole
	// header block, and protobuf framing. The message schema bounds none of those,
	// so the allowance is assumed rather than computed. 1 MiB is what net/http
	// grants a request header block by default, so a message needing more than
	// this on top of its body is not carrying an exchange a mainstream HTTP server
	// would have accepted, while the allowance stays negligible against body
	// limits measured in tens of megabytes.
	//
	// This is why a ceiling is never just the body limit: that would reject a
	// maximum-size body the moment its URL and headers were counted.
	tunnelMessageOverheadBytes = 1 << 20

	// maxCeilingBodySizeMB is the largest body limit that still yields a ceiling
	// an int holds on every platform.
	maxCeilingBodySizeMB = (math.MaxInt32 - tunnelMessageOverheadBytes) / bytesPerMB
)

// tunnelReadMaxBytes is the ceiling for a message arriving from the control
// plane. Inbound messages carry an upstream request body, so the ceiling tracks
// the request body limit.
func tunnelReadMaxBytes(cfg *config.Config) int {
	return tunnelMessageCeiling(cfg.MaxRequestBodySizeMB)
}

// tunnelSendMaxBytes is the ceiling for a message leaving for the control plane.
// Outbound messages carry an upstream response body, so the ceiling tracks the
// response body limit.
func tunnelSendMaxBytes(cfg *config.Config) int {
	return tunnelMessageCeiling(cfg.MaxResponseBodySizeMB)
}

// tunnelMessageCeiling turns a body-size limit in MB into a per-message ceiling
// in bytes. A non-positive limit means unbounded, matching how the body checks
// read the same configuration.
func tunnelMessageCeiling(bodySizeMB int64) int {
	if bodySizeMB <= 0 {
		return unlimitedMessageSize
	}
	// Clamped before the multiplication because an overflowing product comes out
	// negative, which the transport reads as no ceiling at all - the opposite of
	// what a large limit asks for.
	clamped := min(bodySizeMB, maxCeilingBodySizeMB)
	return int(clamped*bytesPerMB) + tunnelMessageOverheadBytes
}
