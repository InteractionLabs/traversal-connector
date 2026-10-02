package rawtunnel

import "net/http"

// ConfigureHTTP2 sets the timeouts a raw-tunnel client or server needs on cfg
// and leaves every other field alone, including MaxConcurrentStreams.
//
// SendPingTimeout and PingTimeout close a connection that stops answering
// HTTP/2 pings. The peer's HTTP/2 stack answers those even while a slow
// destination has filled the stream window, and a stopped process does not.
// WriteByteTimeout closes a connection whose TCP write has stopped making
// progress. It does not run during flow-control backpressure, because no
// bytes are handed to the connection then. A stream write deadline cannot
// take its place: the reset it queues cannot pass a stalled connection write.
func ConfigureHTTP2(cfg *http.HTTP2Config) {
	cfg.SendPingTimeout = DefaultPingInterval
	cfg.PingTimeout = DefaultPingTimeout
	cfg.WriteByteTimeout = DefaultWriteByteTimeout
}
