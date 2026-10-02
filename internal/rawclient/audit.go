package rawclient

import (
	"log/slog"
	"time"
)

// pipeAudit is the one metadata record written for a pipe. It never carries a
// capability, a credential, an authorization header, or a payload byte.
type pipeAudit struct {
	ConnectorID  string
	TunnelID     string
	PipeID       uint64
	Organization string
	Integration  string
	JTI          string
	SessionID    string
	ConsumerID   string
	TrafficClass string
	Host         string
	Port         uint32
	Hostname     string
	Opened       time.Time
	Closed       time.Time
	BytesSent    int64
	BytesRecv    int64
	Outcome      string
	Reason       string
}

func (a pipeAudit) log(logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info("raw pipe",
		"connector_id", a.ConnectorID,
		"tunnel_id", a.TunnelID,
		"pipe_id", a.PipeID,
		"organization_id", a.Organization,
		"integration_id", a.Integration,
		"jti", a.JTI,
		"session_id", a.SessionID,
		"consumer_id", a.ConsumerID,
		"traffic_class", a.TrafficClass,
		"destination", a.Host,
		"port", a.Port,
		"connector_hostname", a.Hostname,
		"opened_at", a.Opened.UTC().Format(time.RFC3339Nano),
		"closed_at", a.Closed.UTC().Format(time.RFC3339Nano),
		"bytes_sent", a.BytesSent,
		"bytes_received", a.BytesRecv,
		"duration_ms", a.Closed.Sub(a.Opened).Milliseconds(),
		"outcome", a.Outcome,
		"reason", a.Reason,
	)
}
