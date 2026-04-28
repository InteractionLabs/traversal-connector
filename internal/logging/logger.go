package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	sloggin "github.com/samber/slog-gin"
)

// ANSI color codes.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorBlue   = "\033[34m"
)

// Color mapping per level.
func levelColor(l slog.Level) string {
	switch {
	case l <= slog.LevelDebug:
		return colorBlue
	case l == slog.LevelInfo:
		return colorGreen
	case l == slog.LevelWarn:
		return colorYellow
	default: // slog.LevelError and above
		return colorRed
	}
}

type TextHandler struct {
	w      io.Writer
	mu     *sync.Mutex
	attrs  []slog.Attr
	groups []string
}

func NewTextHandler(w io.Writer) *TextHandler {
	return &TextHandler{
		w:  w,
		mu: &sync.Mutex{},
	}
}

func (handler *TextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	// Could add level filtering here if you want
	return true
}

func (handler *TextHandler) Handle(ctx context.Context, record slog.Record) error {
	handler.mu.Lock()
	defer handler.mu.Unlock()

	var b strings.Builder

	// Time
	t := record.Time
	if t.IsZero() {
		t = time.Now()
	}
	if _, err := b.WriteString(t.Format("2006-01-02 15:04:05.000")); err != nil {
		return err
	}
	if _, err := b.WriteString(" "); err != nil {
		return err
	}

	// Colored level
	levelStr := strings.ToUpper(record.Level.String())
	if _, err := b.WriteString(levelColor(record.Level)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(&b, "%-5s", levelStr); err != nil {
		return err
	}
	if _, err := b.WriteString(colorReset); err != nil {
		return err
	}
	if _, err := b.WriteString(" "); err != nil {
		return err
	}

	// Source: file:line
	if src := record.Source(); src != nil {
		file := src.File
		if i := strings.LastIndex(file, "/"); i != -1 {
			file = file[i+1:]
		}
		if _, err := fmt.Fprintf(&b, "%s:%d ", file, src.Line); err != nil {
			return err
		}
	}

	// Message
	if _, err := b.WriteString(record.Message); err != nil {
		return err
	}

	// Groups prefix (for attrs)
	var groupPrefix string
	if len(handler.groups) > 0 {
		groupPrefix = strings.Join(handler.groups, ".") + "."
	}

	writeAttr := func(a slog.Attr) error {
		// If you care about LogValuer, you can manually resolve it:
		// if lv, ok := a.Value.Any().(slog.LogValuer); ok {
		//     a = slog.Any(a.Key, lv.LogValue())
		// }

		key := groupPrefix + a.Key
		_, err := fmt.Fprintf(&b, " %s=%v", key, a.Value.Any())
		return err
	}

	// Handler-level attrs (from WithAttrs)
	for _, a := range handler.attrs {
		if err := writeAttr(a); err != nil {
			return err
		}
	}

	requestID := ctx.Value(sloggin.RequestIDContextKey)
	requestIDString, ok := requestID.(string)
	if ok && requestIDString != "" {
		if err := writeAttr(slog.String(sloggin.RequestIDKey, requestIDString)); err != nil {
			return err
		}
	}

	// Record attrs
	var attrErr error
	record.Attrs(func(a slog.Attr) bool {
		if err := writeAttr(a); err != nil {
			attrErr = err
			return false
		}
		return true
	})
	if attrErr != nil {
		return attrErr
	}

	if _, err := b.WriteString("\n"); err != nil {
		return err
	}

	_, err := io.WriteString(handler.w, b.String())
	return err
}

func (handler *TextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(handler.attrs)+len(attrs))
	copy(newAttrs, handler.attrs)
	copy(newAttrs[len(handler.attrs):], attrs)

	return &TextHandler{
		w:      handler.w,
		mu:     handler.mu,
		attrs:  newAttrs,
		groups: handler.groups,
	}
}

func (handler *TextHandler) WithGroup(name string) slog.Handler {
	newGroups := make([]string, len(handler.groups)+1)
	copy(newGroups, handler.groups)
	newGroups[len(handler.groups)] = name

	return &TextHandler{
		w:      handler.w,
		mu:     handler.mu,
		attrs:  handler.attrs,
		groups: newGroups,
	}
}
