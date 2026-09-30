package telemetry

// Span names emitted by the traversal connector.
const (
	SpanConnectorHandleHTTP  = "connector.handle_http_request"
	SpanExecutorUpstreamHTTP = "executor.upstream_http"
)

// Metric names emitted by the traversal connector.
const (
	MetricStreamsActive                    = "connector.streams_active"
	MetricUpstreamRequestsTotal            = "connector.upstream_requests_total"
	MetricUpstreamLatency                  = "connector.upstream_latency"
	MetricReconnectsTotal                  = "connector.reconnects_total"
	MetricUpstreamRequestBodySize          = "connector.upstream_request_body_size"
	MetricUpstreamResponseBodySize         = "connector.upstream_response_body_size"
	MetricConcurrentRequests               = "connector.concurrent_requests"
	MetricResponseSendWaitLatency          = "connector.response_send_wait_latency"
	MetricRequestBodySizeLimitHitConnector = "connector.request_body_size_limit_hit_total"
	MetricRedactionLatencyPerByte          = "connector.redaction_latency_per_byte"
	MetricRedactionHitsTotal               = "connector.redaction_hits_total"
	MetricResponseContentEncodingTotal     = "connector.response_content_encoding_total"
	MetricResponseRefusalsTotal            = "connector.response_refusals_total"
	MetricDecodedResponseBodySize          = "connector.decoded_response_body_size"
	MetricRawTunnelsActive                 = "connector.raw_tunnels_active"
	MetricRawTunnelsDraining               = "connector.raw_tunnels_draining"
	MetricRawPipesActive                   = "connector.raw_pipes_active"
	MetricRawOpensTotal                    = "connector.raw_opens_total"
	MetricRawPipeClosesTotal               = "connector.raw_pipe_closes_total"
	MetricRawPipeBytes                     = "connector.raw_pipe_bytes"
	MetricRawPipeDuration                  = "connector.raw_pipe_duration"
	MetricRawControlRecordsDroppedTotal    = "connector.raw_control_records_dropped_total"
	MetricRawHalfClosesTotal               = "connector.raw_half_closes_total"
	MetricRawDrainsTotal                   = "connector.raw_drains_total"
	MetricRawReconnectsTotal               = "connector.raw_reconnects_total"
	MetricRawClockSkew                     = "connector.raw_clock_skew"
	MetricRawResetsTotal                   = "connector.raw_resets_total"
)
