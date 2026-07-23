package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	logDirPerm  = 0o755
	logFilePerm = 0o644
)

// NewLogWriter opens the file that backs the file log sink and returns it
// alongside a close func the caller must invoke on shutdown. The parent
// directory is created if absent — the log file typically lives on a shared
// volume whose leaf directory the mount may not itself provide.
func NewLogWriter(path string) (io.Writer, func() error, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, logDirPerm); err != nil {
		return nil, nil, fmt.Errorf("create log directory %s: %w", dir, err)
	}

	//nolint:gosec // G304: path is the operator-supplied LOG_FILE_PATH, not user input.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, logFilePerm)
	if err != nil {
		return nil, nil, fmt.Errorf("open log file %s: %w", path, err)
	}
	return f, f.Close, nil
}
