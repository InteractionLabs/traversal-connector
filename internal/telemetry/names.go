package telemetry

// Span names emitted by the traversal connector.
const (
	SpanConnectorHandleHTTP  = "connector.handle_http_request"
	SpanExecutorUpstreamHTTP = "executor.upstream_http"
)

// OpenTelemetry attribute keys emitted by the traversal connector.
const (
	AttrURL = "url"
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
)
