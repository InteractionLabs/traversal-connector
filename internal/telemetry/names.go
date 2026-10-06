package telemetry

// Span names emitted by the traversal connector.
const (
	SpanConnectorHandleHTTP  = "connector.handle_http_request"
	SpanExecutorUpstreamHTTP = "executor.upstream_http"
)

// Metric names emitted by the traversal connector.
const (
	MetricConfigRefreshTotal               = "connector.config_refresh_total"
	MetricConfigRuleCount                  = "connector.config_rule_count"
	MetricConfigStaleness                  = "connector.config_staleness_seconds"
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
)

// Raw pipe metric names. They follow traversal-connector#77's raw tunnel
// names where the meaning is the same.
const (
	MetricRawTunnelsActive                = "connector.raw_tunnels_active"
	MetricRawPipesActive                  = "connector.raw_pipes_active"
	MetricRawOpensTotal                   = "connector.raw_opens_total"
	MetricRawPipeClosesTotal              = "connector.raw_pipe_closes_total"
	MetricRawPipeBytes                    = "connector.raw_pipe_bytes"
	MetricRawPipeDuration                 = "connector.raw_pipe_duration"
	MetricRawResetsTotal                  = "connector.raw_resets_total"
	MetricRawDrainsTotal                  = "connector.raw_drains_total"
	MetricRawCapabilityVerificationsTotal = "connector.raw_capability_verifications_total"
	MetricRawCapabilityRejectionsTotal    = "connector.raw_capability_rejections_total"
	MetricRawKeyLoadsTotal                = "connector.raw_key_loads_total"
)
