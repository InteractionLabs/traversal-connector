package logging

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewLogWriterWritesToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connector.log")

	w, closeFn, err := NewLogWriter(path)
	if err != nil {
		t.Fatalf("NewLogWriter(%q) returned error: %v", path, err)
	}
	if closeFn == nil {
		t.Fatal("expected non-nil close func when path is set")
	}
	t.Cleanup(func() {
		if err := closeFn(); err != nil {
			t.Errorf("close func returned error: %v", err)
		}
	})

	const line = "structured-log-line\n"
	if _, err := w.Write([]byte(line)); err != nil {
		t.Fatalf("write to log file failed: %v", err)
	}

	got, err := os.ReadFile(path) //nolint:gosec // G304: path is under t.TempDir()
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if string(got) != line {
		t.Errorf("log file content = %q, want %q", got, line)
	}
}

// The typical value /var/log/traversal/connector.log lands in a directory the
// shared-volume mount may not itself provide, so the missing parent must be
// created rather than surfaced as an error.
func TestNewLogWriterCreatesMissingParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "connector.log")

	w, closeFn, err := NewLogWriter(path)
	if err != nil {
		t.Fatalf("NewLogWriter(%q) returned error: %v", path, err)
	}
	t.Cleanup(func() { _ = closeFn() })

	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatalf("write to log file failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected log file to exist: %v", err)
	}
}

func TestNewLogWriterAppendsToExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connector.log")
	if err := os.WriteFile(path, []byte("first\n"), logFilePerm); err != nil {
		t.Fatalf("seed log file: %v", err)
	}

	w, closeFn, err := NewLogWriter(path)
	if err != nil {
		t.Fatalf("NewLogWriter(%q) returned error: %v", path, err)
	}
	t.Cleanup(func() { _ = closeFn() })

	if _, err := w.Write([]byte("second\n")); err != nil {
		t.Fatalf("write to log file failed: %v", err)
	}

	got, err := os.ReadFile(path) //nolint:gosec // G304: path is under t.TempDir()
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if want := "first\nsecond\n"; string(got) != want {
		t.Errorf("log file content = %q, want %q", got, want)
	}
}

func TestNewLogWriterErrorsWhenParentIsFile(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), logFilePerm); err != nil {
		t.Fatalf("seed blocker file: %v", err)
	}
	path := filepath.Join(blocker, "connector.log")

	if _, _, err := NewLogWriter(path); err == nil {
		t.Error("expected error when parent path is a regular file, got nil")
	}
}
