package client

import (
	"log/slog"
	"math"
	"strings"

	"connectrpc.com/connect"

	"github.com/InteractionLabs/traversal-connector/internal/config"
)

const (
	bytesPerMB = 1024 * 1024

	// unlimitedMessageSize is how the transport spells "no ceiling".
	unlimitedMessageSize = 0

	// maxHeaderBlockBytes is the largest header block that can reach a tunnel
	// message. net/http allows a response header block 10 MiB by default and the
	// executor's transport does not narrow it, so in the direction the connector
	// does not control this is the bound that actually applies.
	maxHeaderBlockBytes = 10 << 20

	// tunnelMessageFieldsBytes covers what a message carries besides its body and
	// its headers: the request id, the method, the target URL, and protobuf
	// framing. The message schema bounds none of them - the URL least of all - so
	// this is a deliberately generous round number rather than a computed total.
	tunnelMessageFieldsBytes = 2 << 20

	// tunnelMessageOverheadBytes is the room a message needs beyond its body. It
	// has to exceed the header budget above rather than match it, since the header
	// block is only part of what travels alongside the body.
	//
	// This is why a ceiling is never just the body limit: that would reject a
	// maximum-size body the moment its URL and headers were counted.
	tunnelMessageOverheadBytes = maxHeaderBlockBytes + tunnelMessageFieldsBytes

	// maxCeilingBodySizeMB is the largest body limit a ceiling can express, set by
	// the width of the int the transport takes. On a 64-bit platform no
	// configurable limit comes close; a narrower platform is reported rather than
	// quietly held to a different number.
	maxCeilingBodySizeMB = (math.MaxInt - tunnelMessageOverheadBytes) / bytesPerMB
)

// tunnelReadMaxBytes is the ceiling for a message arriving from the control
// plane. Inbound messages carry an upstream request body, which the connector
// refuses above the request body limit, so the ceiling tracks that limit.
func tunnelReadMaxBytes(cfg *config.Config) int {
	return tunnelMessageCeiling(cfg.MaxRequestBodySizeMB)
}

// tunnelSendMaxBytes is the ceiling for a message leaving for the control plane.
//
// The two directions are not symmetric. A response body can leave larger than it
// arrived: to redact a compressed body the connector decodes it, and what it
// re-encodes and sends is bounded by the decoded limit rather than by the wire
// limit that governed arrival. The re-encode is its own compressor at its own
// level, under no obligation to match however the upstream compressed, so its
// output can exceed the bytes that came in. Neither limit dominates the other by
// configuration, so the ceiling follows whichever is larger.
//
// A replacement string longer than the text it matches can still grow a body past
// both limits. That is a property of the configured rules, not something a ceiling
// derived from sizes can predict.
func tunnelSendMaxBytes(cfg *config.Config) int {
	// Either limit unset leaves the body that can leave unbounded, so the ceiling
	// is too - the body checks read a non-positive limit the same way.
	if cfg.MaxResponseBodySizeMB <= 0 || cfg.MaxDecodedResponseBodySizeMB <= 0 {
		return unlimitedMessageSize
	}
	return tunnelMessageCeiling(
		max(cfg.MaxResponseBodySizeMB, cfg.MaxDecodedResponseBodySizeMB),
	)
}

// tunnelMessageCeiling turns a body-size limit in MB into a per-message ceiling
// in bytes. A non-positive limit means unbounded, matching how the body checks
// read the same configuration.
func tunnelMessageCeiling(bodySizeMB int64) int {
	if bodySizeMB <= 0 {
		return unlimitedMessageSize
	}
	if exceedsExpressibleCeiling(bodySizeMB) {
		// The largest ceiling this platform can hold. Multiplying instead would
		// overflow to a negative number, which the transport reads as no ceiling at
		// all - the opposite of what a large limit asks for.
		return math.MaxInt
	}
	return int(bodySizeMB*bytesPerMB) + tunnelMessageOverheadBytes
}

// exceedsExpressibleCeiling reports a body limit too large to convert into a
// ceiling, so the caller can say the configured value is not the one in force.
func exceedsExpressibleCeiling(bodySizeMB int64) bool {
	return bodySizeMB > maxCeilingBodySizeMB
}

// warnOnInexpressibleCeiling reports a configured body limit this platform cannot
// turn into a ceiling, so an operator is not left believing a number that is not
// the one being enforced.
func warnOnInexpressibleCeiling(cfg *config.Config) {
	for setting, bodySizeMB := range map[string]int64{
		"MAX_REQUEST_BODY_SIZE_MB":          cfg.MaxRequestBodySizeMB,
		"MAX_RESPONSE_BODY_SIZE_MB":         cfg.MaxResponseBodySizeMB,
		"MAX_DECODED_RESPONSE_BODY_SIZE_MB": cfg.MaxDecodedResponseBodySizeMB,
	} {
		if exceedsExpressibleCeiling(bodySizeMB) {
			slog.Warn(
				"body size limit is too large to express as a tunnel message ceiling; "+
					"enforcing the largest ceiling this platform holds",
				"setting", setting,
				"configured_mb", bodySizeMB,
				"largest_expressible_mb", int64(maxCeilingBodySizeMB),
			)
		}
	}
}

// messageSizeRefusalMarkers are how the transport phrases a refusal for exceeding
// a configured ceiling, in either direction and whether or not the message was
// compressed. The library offers no sentinel or distinct code for these, so the
// phrasing is all there is to identify one.
//
// Matching on text is sound only because the caller has already established the
// error was raised on this side: a peer cannot supply wording that lands here. A
// transport upgrade that rewords them makes this stop recognising a refusal, which
// is why the tests drive real refusals through the transport rather than
// constructing the error.
var messageSizeRefusalMarkers = []string{
	"larger than configured max",
	"exceeds sendMaxBytes",
}

// isLocalMessageSizeError reports whether err is this side refusing a message for
// exceeding a configured ceiling.
//
// Two other errors share the resource-exhausted code and each has to be ruled out,
// because a caller acting on this predicate names a body-size setting and would
// otherwise send an operator to the wrong one:
//
//   - The controller reporting exhaustion of its own, which is a capacity problem
//     with a different fix. That error arrives from the wire.
//   - A peer ending the stream to ask for less traffic, which the transport turns
//     into local exhaustion even though nothing was oversized. That one is local,
//     so only its subject separates it from a ceiling refusal.
func isLocalMessageSizeError(err error) bool {
	if connect.CodeOf(err) != connect.CodeResourceExhausted || connect.IsWireError(err) {
		return false
	}
	message := err.Error()
	for _, marker := range messageSizeRefusalMarkers {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}
