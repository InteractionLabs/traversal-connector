package redact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/pelletier/go-toml/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/InteractionLabs/traversal-connector/internal/telemetry"
)

// MaxConfigBytes bounds both decoded HTTP bodies and the publishing contract.
const MaxConfigBytes = 1024 * 1024

// ParseConfig rejects unknown fields/types and incomplete documents rather than
// accidentally replacing working redaction with an empty or partial ruleset.
// A deliberate disable is schema_version=1, [redaction], rules=[].
func ParseConfig(data []byte) (*RulesFile, error) {
	if len(data) > MaxConfigBytes {
		return nil, errors.New("config exceeds 1 MiB")
	}
	var doc struct {
		SchemaVersion int `toml:"schema_version"`
		Redaction     *struct {
			DefaultReplacement string  `toml:"default_replacement"`
			Rules              *[]Rule `toml:"rules"`
		} `toml:"redaction"`
	}
	if err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(&doc); err != nil {
		// Do not include a decoder error: it can contain customer rule contents.
		return nil, errors.New("invalid config TOML or unknown fields")
	}
	if doc.SchemaVersion != 1 || doc.Redaction == nil || doc.Redaction.Rules == nil {
		return nil, errors.New("config requires schema_version=1 and explicit redaction.rules")
	}
	names := make(map[string]bool)
	for _, rule := range *doc.Redaction.Rules {
		if rule.Name == "" || names[rule.Name] || rule.Pattern == "" {
			return nil, errors.New("rules require unique nonempty names and nonempty patterns")
		}
		names[rule.Name] = true
		if rule.Type != ruleTypeRegex && rule.Type != ruleTypeRegexStructured {
			return nil, errors.New("unsupported redaction rule type")
		}
		if rule.Type == ruleTypeRegex && (rule.RedactFields != nil || rule.SkipFields != nil) {
			return nil, errors.New("field filters require regex-structured-data")
		}
	}
	return &RulesFile{
		DefaultReplacement: doc.Redaction.DefaultReplacement,
		Rules:              *doc.Redaction.Rules,
	}, nil
}

// ValidateConfig uses the same parser and compiler as RemoteLoader/Update,
// without creating metrics or applying rules. Diagnostics omit rule contents.
func ValidateConfig(data []byte) error {
	rules, err := ParseConfig(data)
	if err != nil {
		return err
	}
	if _, err = compileRules(rules); err != nil {
		return errors.New("redaction pattern or host expression failed to compile")
	}
	return nil
}

// remoteStatus is immutable after publication; metric callbacks may read it
// concurrently with the single polling goroutine.
type remoteStatus struct {
	rules       int64
	lastSuccess time.Time
}

// RemoteLoader polls one authenticated config URL. Call LoadInitial before
// starting tunnels, then Run in a goroutine. Fetch state is single-writer.
// Last-known-good is in memory, not persisted to a local file.
type RemoteLoader struct {
	client   *http.Client
	url      string
	redactor *Redactor
	interval time.Duration
	etag     string
	hash     [sha256.Size]byte
	loaded   bool
	status   atomic.Pointer[remoteStatus]
	outcomes metric.Int64Counter
}

func NewRemoteLoader(
	client *http.Client,
	url string,
	r *Redactor,
	interval time.Duration,
) (*RemoteLoader, error) {
	if client == nil || r == nil || url == "" || interval <= 0 || interval > 24*time.Hour {
		return nil, errors.New(
			"config loader requires client, URL, redactor and interval in (0, 24h]",
		)
	}
	// Never follow redirects with the customer's certificate or allow a stalled
	// endpoint to prevent shutdown indefinitely, even if a caller omitted these.
	bounded := *client
	bounded.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	bounded.Timeout = 15 * time.Second
	l := &RemoteLoader{client: &bounded, url: url, redactor: r, interval: interval}
	l.status.Store(&remoteStatus{})
	meter := otel.Meter(instrumentationName)
	var err error
	l.outcomes, err = meter.Int64Counter(telemetry.MetricConfigRefreshTotal)
	if err != nil {
		return nil, fmt.Errorf("config refresh metric: %w", err)
	}
	_, err = meter.Int64ObservableGauge(telemetry.MetricConfigRuleCount,
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(l.status.Load().rules)
			return nil
		}))
	if err != nil {
		return nil, fmt.Errorf("config rule count metric: %w", err)
	}
	_, err = meter.Float64ObservableGauge(telemetry.MetricConfigStaleness,
		metric.WithUnit("s"),
		metric.WithFloat64Callback(func(_ context.Context, observer metric.Float64Observer) error {
			if last := l.status.Load().lastSuccess; !last.IsZero() {
				observer.Observe(time.Since(last).Seconds())
			}
			return nil
		}))
	if err != nil {
		return nil, fmt.Errorf("config staleness metric: %w", err)
	}
	return l, nil
}

// LoadInitial requires a valid document before startup, even if it explicitly
// contains no rules. Missing config is an error, not permission to run unredacted.
func (l *RemoteLoader) LoadInitial(ctx context.Context) error {
	return l.refresh(ctx)
}

func (l *RemoteLoader) refresh(ctx context.Context) (err error) {
	outcome := "error"
	defer func() {
		l.outcomes.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.url, nil)
	if err != nil {
		return errors.New("invalid config request")
	}
	if l.etag != "" {
		req.Header.Set("If-None-Match", l.etag)
	}
	// ConfigURL derives this URL solely from the validated controller origin.
	// #nosec G704 -- Same-origin endpoint; redirects are disabled by the loader.
	resp, err := l.client.Do(req)
	if err != nil {
		return fmt.Errorf("config fetch failed: %w", telemetry.SanitizeError(err))
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotFound:
		if l.loaded {
			return errors.New(
				"previously loaded config is missing; retaining last-known-good rules",
			)
		}
		return errors.New(
			"config endpoint returned HTTP 404; publish a valid config before enabling OTA",
		)
	case http.StatusNotModified:
		if !l.loaded || l.etag == "" {
			return errors.New("unexpected config 304 without an accepted version")
		}
		outcome = "unchanged"
	case http.StatusOK:
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxConfigBytes+1))
		if readErr != nil {
			return errors.New("could not read config response")
		}
		hash := sha256.Sum256(data)
		if !l.loaded || hash != l.hash {
			rules, parseErr := ParseConfig(data)
			if parseErr != nil {
				return parseErr
			}
			if updateErr := l.redactor.Update(rules); updateErr != nil {
				return errors.New("config rules failed to compile; retaining last-known-good rules")
			}
			l.status.Store(&remoteStatus{rules: int64(len(rules.Rules))})
			outcome = "applied"
			slog.InfoContext(
				ctx,
				"remote redaction config applied",
				"schema_version",
				1,
				"etag",
				resp.Header.Get("ETag"),
				"rule_count",
				len(rules.Rules),
			)
		} else {
			outcome = "unchanged"
		}
		// Only cache a version AFTER its rules were successfully compiled/applied.
		l.hash, l.etag, l.loaded = hash, resp.Header.Get("ETag"), true
	default:
		return fmt.Errorf("config endpoint returned HTTP %d", resp.StatusCode)
	}
	l.status.Store(&remoteStatus{rules: l.status.Load().rules, lastSuccess: time.Now()})
	return nil
}

// Run retains last-known-good indefinitely on failures (including repeated
// 404s); operators see failures and staleness rather than a restart disabling
// redaction. Jitter avoids synchronized fleet-wide polling.
func (l *RemoteLoader) Run(ctx context.Context) {
	for {
		//nolint:gosec // Poll jitter is not used for secrets or authorization.
		delay := time.Duration(float64(l.interval) * (0.9 + 0.1*rand.Float64()))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			if err := l.refresh(ctx); err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "remote config refresh failed", "error", err)
			}
		}
	}
}
