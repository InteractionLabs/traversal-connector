package telemetry

// Span names emitted by the traversal connector.
const (
	SpanUpstreamHTTP = "executor.upstream_http"
)

// Metric names emitted by the traversal connector.
const (
	MetricConfigRefreshTotal           = "connector.config_refresh_total"
	MetricConfigRuleCount              = "connector.config_rule_count"
	MetricConfigStaleness              = "connector.config_staleness_seconds"
	MetricUpstreamRequestsTotal        = "connector.upstream_requests_total"
	MetricUpstreamLatency              = "connector.upstream_latency"
	MetricRedactionLatencyPerByte      = "connector.redaction_latency_per_byte"
	MetricRedactionHitsTotal           = "connector.redaction_hits_total"
	MetricResponseContentEncodingTotal = "connector.response_content_encoding_total"
	MetricResponseRefusalsTotal        = "connector.response_refusals_total"
	MetricDecodedResponseBodySize      = "connector.decoded_response_body_size"
	// Raw pipes (internal/pipeserver).
	MetricRawTunnelsUp       = "connector.raw_tunnels_up"
	MetricRawTunnelDialTotal = "connector.raw_tunnel_dial_total"
	MetricRawPipeOpenTotal   = "connector.raw_pipe_open_total"
	MetricRawPipes           = "connector.raw_pipes"
	MetricRawPipeEndTotal    = "connector.raw_pipe_end_total"
	MetricRawPipeBytes       = "connector.raw_pipe_bytes_total"
	MetricCapabilityTrust    = "connector.capability_trust"
)
