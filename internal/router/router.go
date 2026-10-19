package router

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	sloggin "github.com/samber/slog-gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

	"github.com/InteractionLabs/traversal-connector/internal/config"
)

// Tunnels is the connector's tunnels as readiness sees them.
type Tunnels interface {
	// Up is how many tunnels are up.
	Up() int
	// Ready is nil if the connector can take pipes, and otherwise why not.
	Ready(ctx context.Context) error
}

// NewRouter creates a gin HTTP engine for the traversal connector with health and
// readiness endpoints. Readiness is the tunnels'.
func NewRouter(cfg config.Config, tunnels Tunnels) *gin.Engine {
	if cfg.EnvLevel.IsDev() {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	r.Use(gin.Recovery())

	// otelgin must be registered before sloggin so the span is still
	// recording when sloggin logs (span.End() is deferred by otelgin,
	// and sloggin's extractTraceSpanID checks span.IsRecording()).
	r.Use(otelgin.Middleware(cfg.OTELServiceName))

	if !cfg.EnvLevel.IsDev() {
		logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
		r.Use(sloggin.NewWithConfig(logger, sloggin.Config{
			WithTraceID: true,
			WithSpanID:  true,
		}))
	} else {
		r.Use(gin.Logger())
	}

	r.GET("/healthz", healthCheckHandler)
	r.GET("/readyz", gin.WrapH(Readiness(tunnels)))

	return r
}

func healthCheckHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
	})
}

// Readiness answers /readyz, and probes: requests in a pipe to
// rawpipe.ProbeAuthority, so the status probe reads the same body either
// way. active_tunnels is the field it parses.
func Readiness(tunnels Tunnels) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{"status": "ready", "active_tunnels": tunnels.Up()}
		status := http.StatusOK
		if err := tunnels.Ready(r.Context()); err != nil {
			body["status"], body["reason"], status = "not ready", err.Error(),
				http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	})
}
