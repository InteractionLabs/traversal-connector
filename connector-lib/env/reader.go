package env

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Reader reads settings strictly: a setting that is set but invalid is an
// error (Err), not its default. The GetEnv functions fall back silently, so
// a typo quietly runs the default, and their bools take "1" and "T". New
// settings should use a Reader.
type Reader struct{ errs []error }

// Int reads key as an integer from 1 to maxVal, or def if unset.
func (r *Reader) Int(key string, def, maxVal int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > maxVal {
		r.errs = append(r.errs, fmt.Errorf("%s must be 1 to %d, got %q", key, maxVal, v))
	}
	return n
}

// Duration reads key as a non-negative duration, or def if unset.
func (r *Reader) Duration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		r.errs = append(r.errs, fmt.Errorf("%s must be a duration such as 15m, got %q", key, v))
	}
	return d
}

// Bool reads key as exactly "true" or "false", or def if unset.
func (r *Reader) Bool(key string, def bool) bool {
	switch v := os.Getenv(key); v {
	case "":
		return def
	case "false":
		return false
	case "true":
		return true
	default:
		r.errs = append(r.errs, fmt.Errorf("%s must be true or false, got %q", key, v))
		return def
	}
}

// Fail records an invalid setting the caller checked itself.
func (r *Reader) Fail(err error) { r.errs = append(r.errs, err) }

// Err is every invalid setting read so far, or nil.
func (r *Reader) Err() error { return errors.Join(r.errs...) }
