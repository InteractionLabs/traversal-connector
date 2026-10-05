package router

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	sloggin "github.com/samber/slog-gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

	"github.com/InteractionLabs/traversal-connector/internal/client"
	"github.com/InteractionLabs/traversal-connector/internal/config"
)

// ReadinessGate reports whether one part of the connector can take traffic,
// and if not, why.
type ReadinessGate func(ctx context.Context) (ready bool, reason string)

// NewRouter creates a gin HTTP engine for the traversal connector with health and
// readiness endpoints. The connector is ready when it holds a legacy tunnel and
// every gate passes.
func NewRouter(cfg config.Config, cm *client.ConnectionManager, gates ...ReadinessGate) *gin.Engine {
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
	r.GET("/readyz", readinessHandler(cm, gates))

	return r
}

func healthCheckHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
	})
}

func readinessHandler(cm *client.ConnectionManager, gates []ReadinessGate) gin.HandlerFunc {
	return func(c *gin.Context) {
		activeTunnels := cm.ActiveCount()
		if activeTunnels == 0 {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status":         "not ready",
				"active_tunnels": activeTunnels,
				"reason":         "no active tunnel connections",
			})
			return
		}
		for _, gate := range gates {
			if ready, reason := gate(c.Request.Context()); !ready {
				c.JSON(http.StatusServiceUnavailable, gin.H{
					"status":         "not ready",
					"active_tunnels": activeTunnels,
					"reason":         reason,
				})
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"status":         "ready",
			"active_tunnels": activeTunnels,
		})
	}
}
