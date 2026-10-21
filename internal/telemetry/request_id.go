package telemetry

import "context"

type requestIDKey struct{}

// WithRequestID attaches the controller-issued request ID to ctx. The executor
// receives only the HTTP request, not the envelope carrying the ID, so the
// context is how its log lines join the controller's logs for the same request.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, requestID)
}

// RequestIDFromContext returns the request ID set by WithRequestID, or "".
func RequestIDFromContext(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDKey{}).(string)
	return requestID
}
