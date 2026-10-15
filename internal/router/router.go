package router

import (
	"context"
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
	// Ready reports whether the connector can take pipes, and if not, why.
	Ready(ctx context.Context) (ready bool, reason string)
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
	r.GET("/readyz", ReadinessHandler(tunnels))

	return r
}

func healthCheckHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
	})
}

// ReadinessHandler answers /readyz. Pipes to rawpipe.ProbeAuthority get the
// same answer, so the status probe reads the same body either way:
// active_tunnels is the field it parses.
func ReadinessHandler(tunnels Tunnels) gin.HandlerFunc {
	return func(c *gin.Context) {
		body := gin.H{"status": "ready", "active_tunnels": tunnels.Up()}
		status := http.StatusOK
		if ready, reason := tunnels.Ready(c.Request.Context()); !ready {
			body["status"], body["reason"], status = "not ready", reason, http.StatusServiceUnavailable
		}
		c.JSON(status, body)
	}
}
