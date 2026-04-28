package redact

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/pelletier/go-toml/v2"
)

const reloadInterval = 10 * time.Second

// ruleType enumerates the supported redaction rule kinds.
type ruleType string

const ruleTypeRegex ruleType = "regex"

// Rule is a single entry in the TOML rules file.
type Rule struct {
	Name        string   `toml:"name"`
	Type        ruleType `toml:"type"`
	Pattern     string   `toml:"pattern"`
	Replacement string   `toml:"replacement"`
}

// RulesFile is the top-level TOML document.
type RulesFile struct {
	Version string `toml:"version"`
	Rules   []Rule `toml:"rules"`
}

// compiledRule is a Rule with its regex pre-compiled and replacement as bytes.
// regexp.ReplaceAll expands $1/$name references in the replacement slice.
type compiledRule struct {
	name        string
	re          *regexp.Regexp
	replacement []byte
}

// Redactor holds a set of compiled redaction rules and applies them atomically.
// The zero value is not usable; use NewRedactor.
type Redactor struct {
	rules atomic.Pointer[[]compiledRule]
}

// NewRedactor returns a Redactor with an empty rule set.
func NewRedactor() *Redactor {
	r := &Redactor{}
	empty := make([]compiledRule, 0)
	r.rules.Store(&empty)
	return r
}

// Update compiles all regex rules from f and atomically replaces the current
// rule set. Rules with an unrecognised type are skipped with a warning.
func (r *Redactor) Update(f *RulesFile) error {
	compiled := make([]compiledRule, 0, len(f.Rules))
	for _, rule := range f.Rules {
		if rule.Type != ruleTypeRegex {
			slog.Warn("redaction rule has unsupported type, skipping",
				"rule", rule.Name, "type", rule.Type)
			continue
		}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Errorf("rule %q: invalid pattern: %w", rule.Name, err)
		}
		compiled = append(compiled, compiledRule{
			name:        rule.Name,
			re:          re,
			replacement: []byte(rule.Replacement),
		})
	}
	r.rules.Store(&compiled)
	return nil
}

// Apply runs all current redaction rules over src and returns the result.
// If there are no rules the original slice is returned unchanged.
func (r *Redactor) Apply(src []byte) []byte {
	rules := *r.rules.Load()
	if len(rules) == 0 {
		return src
	}
	result := src
	for i := range rules {
		result = rules[i].re.ReplaceAll(result, rules[i].replacement)
	}
	return result
}

// FileLoader reloads a TOML redaction rules file every 10 seconds and updates
// the provided Redactor whenever the file changes.
type FileLoader struct {
	path     string
	redactor *Redactor
	lastHash [sha256.Size]byte
}

// NewFileLoader returns a FileLoader that will watch path and push updates to r.
func NewFileLoader(path string, r *Redactor) *FileLoader {
	return &FileLoader{path: path, redactor: r}
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

// Run reloads the rules file every 10 seconds until ctx is cancelled.
// Call LoadInitial before Run to ensure rules are applied from the start.
// After a successful initial load, subsequent errors (missing or corrupted file)
// are logged and the last valid rule set is kept.
func (l *FileLoader) Run(ctx context.Context) {
	ticker := time.NewTicker(reloadInterval)
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

func (l *FileLoader) tryLoad() {
	data, err := os.ReadFile(l.path)
	if err != nil {
		slog.Error("could not read redaction rules file, keeping current rules",
			"path", l.path, "error", err)
		return
	}

	hash := sha256.Sum256(data)
	if hash == l.lastHash {
		return
	}

	var f RulesFile
	if err = toml.Unmarshal(data, &f); err != nil {
		slog.Error("failed to parse redaction rules file, keeping current rules",
			"path", l.path, "error", err)
		return
	}

	if err = l.redactor.Update(&f); err != nil {
		slog.Error("failed to compile redaction rules, keeping current rules",
			"path", l.path, "error", err)
		return
	}

	l.lastHash = hash
	slog.Info("redaction rules reloaded", "path", l.path, "rules", len(f.Rules))
}
