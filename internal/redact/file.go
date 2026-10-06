package redact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// FileLoader polls a local TOML rules file. Call LoadInitial before opening
// tunnels, then Run in a goroutine. Only one goroutine may load at a time.
type FileLoader struct {
	path                string
	redactor            *Redactor
	reloadInterval      time.Duration
	lastHash            [sha256.Size]byte
	loaded              bool
	consecutiveFailures int
}

func NewFileLoader(path string, r *Redactor, interval time.Duration) *FileLoader {
	return &FileLoader{path: path, redactor: r, reloadInterval: interval}
}

// LoadInitial requires a readable, valid file before serving any requests.
func (l *FileLoader) LoadInitial() error {
	if l.path == "" || l.redactor == nil || l.reloadInterval <= 0 {
		return errors.New("local loader requires a path, redactor and positive reload interval")
	}
	return l.refresh()
}

func (l *FileLoader) refresh() error {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return fmt.Errorf("read local redaction rules: %w", err)
	}
	hash := sha256.Sum256(data)
	if l.loaded && hash == l.lastHash {
		return nil
	}
	var rules RulesFile
	if err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(&rules); err != nil {
		// Parser and compiler diagnostics can contain customer rule contents.
		return errors.New("invalid local redaction TOML or unknown fields")
	}
	if err := l.redactor.Update(&rules); err != nil {
		return errors.New(
			"local redaction rules failed to compile; retaining last-known-good rules",
		)
	}
	l.lastHash, l.loaded = hash, true
	slog.Info("local redaction rules applied", "path", l.path, "rule_count", len(rules.Rules))
	return nil
}

const maxConsecutiveFileFailures = 3

// Run retains the last-known-good rules on reload errors. After three
// consecutive failures it returns an error; the caller must stop the connector.
// A successful read, including unchanged content, resets the failure count.
func (l *FileLoader) Run(ctx context.Context) error {
	if !l.loaded {
		return errors.New("local redaction rules must be loaded before polling")
	}
	ticker := time.NewTicker(l.reloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := l.poll(ctx); err != nil {
				return err
			}
		}
	}
}

func (l *FileLoader) poll(ctx context.Context) error {
	if err := l.refresh(); err != nil {
		l.consecutiveFailures++
		slog.WarnContext(ctx, "local redaction reload failed",
			"error", err, "consecutive_failures", l.consecutiveFailures)
		if l.consecutiveFailures >= maxConsecutiveFileFailures {
			return fmt.Errorf(
				"local redaction failed %d consecutive reloads: %w",
				l.consecutiveFailures,
				err,
			)
		}
	} else {
		l.consecutiveFailures = 0
	}
	return nil
}
