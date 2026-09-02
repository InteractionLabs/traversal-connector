package redact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/pelletier/go-toml/v2"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// ruleType enumerates the supported redaction rule kinds.
type ruleType string

const (
	// ruleTypeRegex applies a byte-level regex to the full document. It does
	// not support per-field filters and only fires on the Apply path.
	ruleTypeRegex ruleType = "regex"
	// ruleTypeRegexStructured applies a regex per-field on structured (JSON)
	// data and supports the redact_fields / skip_fields filters. It fires on
	// ApplyJSON (per-field, filter-aware) and on Apply (full document,
	// byte-level, filters ignored).
	ruleTypeRegexStructured ruleType = "regex-structured-data"
)

// defaultDefaultReplacement is used when neither the rule nor the rules file
// specify a replacement string.
const defaultDefaultReplacement = "[REDACTED]"

// fieldPathSeparator is used to join nested JSON field names, matching the
// pipe-delimited GetField convention documented in the spec (e.g. "body|message").
const fieldPathSeparator = "|"

// Rule is a single entry in the TOML rules file.
type Rule struct {
	Name    string   `toml:"name"`
	Type    ruleType `toml:"type"`
	Pattern string   `toml:"pattern"`
	// Replacement is optional. An empty Replacement falls back to the rules
	// file's DefaultReplacement (which itself falls back to "[REDACTED]").
	Replacement string `toml:"replacement"`
	// RedactFields is an optional allowlist of pipe-delimited field names.
	// When set, the rule only runs against those fields on the per-field path.
	RedactFields []string `toml:"redact_fields"`
	// SkipFields is an optional blocklist of pipe-delimited field names.
	// When set, the rule never runs against those fields on the per-field path.
	SkipFields []string `toml:"skip_fields"`
	// Hosts is an optional allowlist of RE2 patterns matched against the request
	// hostname (port stripped). The rule only fires when the hostname fully
	// matches at least one pattern. When empty, it defaults to [".*"], which
	// matches every host. Each pattern is anchored to the whole hostname, so
	// ".*github.com" matches "api.github.com" and "github.com" but not
	// "github.com.evil.com".
	Hosts []string `toml:"hosts"`
}

// RulesFile is the top-level TOML document.
type RulesFile struct {
	Version string `toml:"version"`
	// DefaultReplacement is the fallback replacement string for rules that
	// omit replacement. When empty, "[REDACTED]" is used.
	DefaultReplacement string `toml:"default_replacement"`
	Rules              []Rule `toml:"rules"`
}

// compiledRule is a Rule with its regex pre-compiled and replacement as bytes.
// regexp.ReplaceAll expands $1/$name references in the replacement slice.
type compiledRule struct {
	name        string
	re          *regexp.Regexp
	replacement []byte
	// structured is true for regex-structured-data rules. Only structured
	// rules fire on the per-field ApplyJSON path; both kinds fire on Apply.
	structured bool
	// redactFields / skipFields are nil when the rule has no filter on that
	// side. An empty (non-nil) map means "filter set but nothing in it" — which
	// per spec means the allowlist matches no field, or the blocklist blocks
	// no field. Filters are only consulted on the per-field path. Matches are
	// prefix-based on pipe-delimited paths: an entry "body" matches the field
	// "body" itself plus everything beneath it ("body|message", "body|x|y", …).
	redactFields map[string]struct{}
	skipFields   map[string]struct{}
	// hostMatchers is the compiled, fully-anchored form of Rule.Hosts. A nil
	// slice means "no host filter" — the rule fires on every host (equivalent to
	// the [".*"] default). When non-nil, the rule fires only if the request
	// hostname fully matches at least one matcher.
	hostMatchers []*regexp.Regexp
}

// appliesToHost reports whether the rule should fire for the given request
// hostname. A rule with no host filter (nil hostMatchers) always applies.
func (cr *compiledRule) appliesToHost(host string) bool {
	if cr.hostMatchers == nil {
		return true
	}
	for _, m := range cr.hostMatchers {
		if m.MatchString(host) {
			return true
		}
	}
	return false
}

// HasRulesForHost reports whether any rule of either type fires for host, which
// is the request hostname with the port stripped. Callers use it to skip the
// whole redaction pipeline, including response decoding, on hosts no rule
// targets.
func (r *Redactor) HasRulesForHost(host string) bool {
	rules := *r.rules.Load()
	for i := range rules {
		if rules[i].appliesToHost(host) {
			return true
		}
	}
	return false
}

// hasPathPrefixInSet reports whether field, or any of its pipe-delimited
// ancestor paths, appears in set. "" never matches unless "" is in set.
// E.g. for field="body|message|inner" the prefixes checked are "body",
// "body|message", and "body|message|inner".
func hasPathPrefixInSet(field string, set map[string]struct{}) bool {
	if _, ok := set[field]; ok {
		return true
	}
	for i := 0; i < len(field); i++ {
		if field[i] == fieldPathSeparator[0] {
			if _, ok := set[field[:i]]; ok {
				return true
			}
		}
	}
	return false
}

// Redactor holds a set of compiled redaction rules and applies them atomically.
// The zero value is not usable; use NewRedactor.
type Redactor struct {
	rules   atomic.Pointer[[]compiledRule]
	metrics *redactorMetrics
}

// NewRedactor returns a Redactor with an empty rule set.
func NewRedactor() *Redactor {
	metrics, err := initRedactorMetrics()
	if err != nil {
		slog.Warn("failed to initialize redactor metrics, continuing without metrics", "error", err)
	}
	r := &Redactor{metrics: metrics}
	empty := make([]compiledRule, 0)
	r.rules.Store(&empty)
	return r
}

// Update compiles all rules from f and atomically replaces the current rule
// set.
//
//   - Rules with type "regex" or "regex-structured-data" are compiled.
//     Unrecognised types are logged and skipped.
//   - Each rule's replacement falls back to f.DefaultReplacement, which itself
//     falls back to "[REDACTED]".
//   - redact_fields / skip_fields are only meaningful on
//     "regex-structured-data" rules; if set on a "regex" rule a warning is
//     logged and the filters are ignored (since "regex" has no field concept).
func (r *Redactor) Update(f *RulesFile) error {
	defaultReplacement := f.DefaultReplacement
	if defaultReplacement == "" {
		defaultReplacement = defaultDefaultReplacement
	}

	compiled := make([]compiledRule, 0, len(f.Rules))
	for _, rule := range f.Rules {
		structured := false
		switch rule.Type {
		case ruleTypeRegex:
			if len(rule.RedactFields) > 0 || len(rule.SkipFields) > 0 {
				slog.Warn(
					"redaction rule has field filters but type is \"regex\"; filters are ignored — use \"regex-structured-data\" for per-field redaction",
					"rule",
					rule.Name,
				)
			}
		case ruleTypeRegexStructured:
			structured = true
		default:
			slog.Warn("redaction rule has unsupported type, skipping",
				"rule", rule.Name, "type", rule.Type)
			continue
		}

		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Errorf("rule %q: invalid pattern: %w", rule.Name, err)
		}

		replacement := rule.Replacement
		if replacement == "" {
			replacement = defaultReplacement
		}

		hostMatchers, err := compileHostMatchers(rule.Hosts)
		if err != nil {
			return fmt.Errorf("rule %q: %w", rule.Name, err)
		}

		cr := compiledRule{
			name:         rule.Name,
			re:           re,
			replacement:  []byte(replacement),
			structured:   structured,
			hostMatchers: hostMatchers,
		}
		if structured {
			cr.redactFields = toFieldSet(rule.RedactFields)
			cr.skipFields = toFieldSet(rule.SkipFields)
		}
		compiled = append(compiled, cr)
	}
	r.rules.Store(&compiled)
	return nil
}

// compileHostMatchers compiles each host pattern into a fully-anchored regexp
// so a pattern matches only when it spans the entire hostname. An empty/nil
// patterns slice (or one containing only ".*") returns nil, meaning "match every
// host" — this avoids running a regex per request for the common default case.
func compileHostMatchers(patterns []string) ([]*regexp.Regexp, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	matchers := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if p == ".*" {
			// Matches everything; equivalent to no filter at all.
			return nil, nil
		}
		// Anchor to the whole hostname. The non-capturing group keeps any
		// top-level alternation in p from binding only the first/last branch
		// to the anchors.
		m, err := regexp.Compile("^(?:" + p + ")$")
		if err != nil {
			return nil, fmt.Errorf("invalid host pattern %q: %w", p, err)
		}
		matchers = append(matchers, m)
	}
	return matchers, nil
}

func toFieldSet(fields []string) map[string]struct{} {
	if fields == nil {
		return nil
	}
	s := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		s[f] = struct{}{}
	}
	return s
}

// Apply runs legacy "regex" rules over src and returns the result. Structured
// ("regex-structured-data") rules are skipped here — they're designed for the
// per-field ApplyJSON path and their redact_fields / skip_fields filters can't
// be honored on raw bytes, so firing them globally would surprise callers (it
// would redact across fields the filters explicitly excluded).
//
// Rules whose hosts allowlist does not match host are skipped; host is the
// request hostname (port stripped). A rule with no hosts filter matches every
// host.
//
// The second return value reports whether any rule changed src. Callers use it
// to flag the response and to count redaction hits; it does not affect the
// returned bytes.
//
// If there are no legacy rules the original slice is returned unchanged.
func (r *Redactor) Apply(ctx context.Context, host string, src []byte) ([]byte, bool) {
	rules := *r.rules.Load()
	if len(rules) == 0 {
		return src, false
	}
	result := src
	changed := false
	for i := range rules {
		if rules[i].structured || !rules[i].appliesToHost(host) {
			continue
		}
		var ruleChanged bool
		result, ruleChanged = r.applyOneRule(ctx, &rules[i], result)
		changed = changed || ruleChanged
	}
	return result, changed
}

// ApplyJSON parses src as JSON and applies regex-structured-data rules
// per-field, honoring each rule's redact_fields / skip_fields filters. Nested
// field names are pipe-delimited (e.g. "body|message"). Array elements inherit
// their parent field path — array indices are not part of the path.
//
// Legacy "regex" rules do not fire on this path; callers wanting byte-level
// regex over JSON should use Apply.
//
// Rules whose hosts allowlist does not match host are skipped; host is the
// request hostname (port stripped). A rule with no hosts filter matches every
// host.
//
// The second return value reports whether a rule actually matched, which is not
// the same as the output differing from src: this path re-serializes the
// document, so a body the upstream pretty-printed comes back with different bytes
// and nothing redacted. Callers needing to know that the representation moved
// have to compare the bytes themselves.
//
// If there are no structured rules in scope for host, src is returned
// unchanged. If src is not valid JSON, an error is returned and the caller
// should fall back to Apply.
func (r *Redactor) ApplyJSON(
	ctx context.Context,
	host string,
	src []byte,
) ([]byte, bool, error) {
	rules := *r.rules.Load()
	// Pre-filter to the structured rules in scope for this host so the host
	// regexes run once per request rather than once per JSON node.
	active := make([]compiledRule, 0, len(rules))
	for i := range rules {
		if rules[i].structured && rules[i].appliesToHost(host) {
			active = append(active, rules[i])
		}
	}
	if len(active) == 0 {
		return src, false, nil
	}

	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, false, fmt.Errorf("redact: parse json: %w", err)
	}

	matched := false
	value = r.redactValue(ctx, value, "", active, &matched)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, false, fmt.Errorf("redact: marshal json: %w", err)
	}
	// json.Encoder.Encode appends a trailing newline; strip it to keep the
	// output byte-for-byte comparable to a normal Marshal.
	return bytes.TrimRight(buf.Bytes(), "\n"), matched, nil
}

// redactValue runs every structured rule over v independently. Each rule's
// scope is determined by its own redact_fields / skip_fields, so two rules
// targeting different subtrees compose cleanly.
func (r *Redactor) redactValue(
	ctx context.Context,
	v any,
	fieldPath string,
	rules []compiledRule,
	matched *bool,
) any {
	for i := range rules {
		if !rules[i].structured {
			continue
		}
		v = r.redactValueForRule(ctx, v, fieldPath, &rules[i], matched)
	}
	return v
}

// redactValueForRule walks v applying a single structured rule.
//
// A node at fieldPath is "in scope" when the rule has no redact_fields, or
// when some ancestor path (or fieldPath itself) appears in redact_fields —
// i.e. the node sits inside a targeted subtree. Once a node is in scope,
// every primary-type leaf reachable from it is redacted: map keys, map
// values, and array elements alike. skip_fields excludes an entire subtree
// by path prefix; both the key and the value of a skipped entry are left
// untouched.
//
// Numbers are matched against their JSON textual form: e.g. an SSN rule of
// \d{3}-\d{2}-\d{4} won't match a bare integer, but a credit-card-style
// pattern will catch 4111111111111111 whether the upstream serialized it as
// a string or a number. When a number actually matches, the field is
// rewritten as a string (the redacted output is no longer a number); when it
// doesn't, the original number is preserved unchanged. Booleans and null
// pass through unchanged.
func (r *Redactor) redactValueForRule(
	ctx context.Context,
	v any,
	fieldPath string,
	rule *compiledRule,
	matched *bool,
) any {
	if rule.skipFields != nil && hasPathPrefixInSet(fieldPath, rule.skipFields) {
		return v
	}
	inScope := rule.redactFields == nil || hasPathPrefixInSet(fieldPath, rule.redactFields)

	switch val := v.(type) {
	case map[string]any:
		// Build a fresh map so a redacted key can replace the original. If two
		// keys collapse to the same redacted form, last-write-wins — JSON
		// objects can't carry duplicate keys, and PII colliding in keys is an
		// edge case we accept rather than try to disambiguate.
		out := make(map[string]any, len(val))
		for k, child := range val {
			childPath := k
			if fieldPath != "" {
				childPath = fieldPath + fieldPathSeparator + k
			}
			if rule.skipFields != nil && hasPathPrefixInSet(childPath, rule.skipFields) {
				out[k] = child
				continue
			}
			newKey := k
			if inScope {
				redactedKey, hit := r.applyOneRule(ctx, rule, []byte(k))
				newKey = string(redactedKey)
				*matched = *matched || hit
			}
			out[newKey] = r.redactValueForRule(ctx, child, childPath, rule, matched)
		}
		return out
	case []any:
		for i, item := range val {
			val[i] = r.redactValueForRule(ctx, item, fieldPath, rule, matched)
		}
		return val
	case string:
		if inScope {
			out, hit := r.applyOneRule(ctx, rule, []byte(val))
			*matched = *matched || hit
			return string(out)
		}
		return val
	case json.Number:
		if inScope {
			redacted, hit := r.applyOneRule(ctx, rule, []byte(val))
			if hit {
				*matched = true
				// A match touched the number — emit as a string so the redacted
				// output (which may not be a valid number anymore) survives
				// re-marshaling.
				return string(redacted)
			}
		}
		return val
	default:
		return v
	}
}

// applyOneRule runs rule over src, returning the result and whether it matched.
//
// The hit counter is per-rule, so an operator can tell a rule that never fires
// from one carrying the whole redaction load. It counts applications, not
// occurrences: one per body for a byte-level rule, one per field for a
// structured rule.
func (r *Redactor) applyOneRule(
	ctx context.Context,
	rule *compiledRule,
	src []byte,
) ([]byte, bool) {
	inputLen := len(src)
	start := time.Now()
	out := rule.re.ReplaceAll(src, rule.replacement)
	changed := !bytes.Equal(out, src)
	if r.metrics != nil {
		ruleAttr := metric.WithAttributes(attribute.String(attrRuleName, rule.name))
		if inputLen > 0 {
			latencyMs := float64(time.Since(start).Microseconds()) / 1000.0
			r.metrics.latencyPerByte.Record(ctx, latencyMs/float64(inputLen), ruleAttr)
		}
		if changed {
			r.metrics.hitsTotal.Add(ctx, 1, ruleAttr)
		}
	}
	return out, changed
}

// FileLoader watches a TOML redaction rules file at a configurable interval and
// updates the provided Redactor whenever the file changes.
type FileLoader struct {
	path                string
	redactor            *Redactor
	reloadInterval      time.Duration
	lastHash            [sha256.Size]byte
	consecutiveFailures int
}

// NewFileLoader returns a FileLoader that will watch path and push updates to r
// every interval.
func NewFileLoader(path string, r *Redactor, interval time.Duration) *FileLoader {
	return &FileLoader{path: path, redactor: r, reloadInterval: interval}
}

// LoadInitial performs the first load of the rules file. Returns an error if
// the file does not exist, cannot be parsed, or contains invalid patterns.
// Must be called before Run; on success the rules are live immediately.
func (l *FileLoader) LoadInitial() error {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return fmt.Errorf("redaction rules file %q: %w", l.path, err)
	}

	var f RulesFile
	if err = toml.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("redaction rules file %q: parse error: %w", l.path, err)
	}

	if err = l.redactor.Update(&f); err != nil {
		return fmt.Errorf("redaction rules file %q: %w", l.path, err)
	}

	l.lastHash = sha256.Sum256(data)
	slog.Info("redaction rules loaded", "path", l.path, "rules", len(f.Rules))
	return nil
}

// Run reloads the rules file on the configured interval until ctx is cancelled.
// Call LoadInitial before Run to ensure rules are applied from the start.
// Each reload error is logged; after 3 consecutive failures the process exits.
func (l *FileLoader) Run(ctx context.Context) {
	ticker := time.NewTicker(l.reloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.tryLoad()
		}
	}
}

const maxConsecutiveFailures = 3

func (l *FileLoader) tryLoad() {
	data, err := os.ReadFile(l.path)
	if err != nil {
		l.recordFailure("could not read redaction rules file", err)
		return
	}

	hash := sha256.Sum256(data)
	if hash == l.lastHash {
		l.consecutiveFailures = 0
		return
	}

	var f RulesFile
	if err = toml.Unmarshal(data, &f); err != nil {
		l.recordFailure("failed to parse redaction rules file", err)
		return
	}

	if err = l.redactor.Update(&f); err != nil {
		l.recordFailure("failed to compile redaction rules", err)
		return
	}

	l.consecutiveFailures = 0
	l.lastHash = hash
	slog.Info("redaction rules reloaded", "path", l.path, "rules", len(f.Rules))
}

func (l *FileLoader) recordFailure(msg string, err error) {
	l.consecutiveFailures++
	slog.Error(msg, "path", l.path, "error", err, "consecutive_failures", l.consecutiveFailures)
	// Maybe they are swapping out the file and it doesn't exist at this instant, or there is a transient IO error.
	// Log and retry on the next tick. If we fail 3 times in a row, something is really wrong and we should exit to avoid
	// running with stale rules indefinitely.
	if l.consecutiveFailures >= maxConsecutiveFailures {
		slog.Error("too many consecutive redaction rule failures, exiting", "path", l.path)
		os.Exit(1)
	}
}
