package env

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// GetEnvString returns the value of the environment variable identified by key,
// or defaultVal if the variable is empty or unset.
func GetEnvString(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// GetEnvInt returns the value of the environment variable identified by key
// parsed as an int, or defaultVal if the variable is empty, unset, or not a valid integer.
func GetEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			return parsed
		}
	}
	return defaultVal
}

// GetEnvInt64 returns the value of the environment variable identified by key
// parsed as an int64, or defaultVal if the variable is empty, unset, or not a valid integer.
func GetEnvInt64(key string, defaultVal int64) int64 {
	if val := os.Getenv(key); val != "" {
		if parsed, err := strconv.ParseInt(val, 10, 64); err == nil {
			return parsed
		}
	}
	return defaultVal
}

// GetEnvDuration returns the value of the environment variable identified by key
// parsed as a time.Duration,
// or defaultVal if the variable is empty, unset, or not a valid duration.
func GetEnvDuration(key string, defaultVal time.Duration) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	if duration, err := time.ParseDuration(val); err == nil {
		return duration
	}
	// If environment value is invalid, return the default
	return defaultVal
}

// GetEnvBool returns the value of the environment variable identified by key
// parsed as a bool, or defaultVal if the variable is empty, unset, or not a valid boolean.
// Accepts "true"/"1" as true and "false"/"0" as false (case-insensitive).
func GetEnvBool(key string, defaultVal bool) bool {
	if val := os.Getenv(key); val != "" {
		if parsed, err := strconv.ParseBool(val); err == nil {
			return parsed
		}
	}
	return defaultVal
}

// ParseBool returns defaultVal when key is unset or empty. A non-empty value
// that is not a bool is an error naming key. The error does not include the
// value, so a mis-set secret is not written to the startup log.
func ParseBool(key string, defaultVal bool) (bool, error) {
	val, ok := os.LookupEnv(key)
	if !ok || val == "" {
		return defaultVal, nil
	}
	parsed, err := strconv.ParseBool(val)
	if err != nil {
		return false, fmt.Errorf("%s is not a valid bool", key)
	}
	return parsed, nil
}

// ParseInt returns defaultVal when key is unset or empty. A non-empty value
// that is not an integer is an error naming key and not the value.
func ParseInt(key string, defaultVal int) (int, error) {
	val, ok := os.LookupEnv(key)
	if !ok || val == "" {
		return defaultVal, nil
	}
	parsed, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("%s is not a valid integer", key)
	}
	return parsed, nil
}

// ParseDuration returns defaultVal when key is unset or empty. A non-empty
// value that is not a Go duration is an error naming key and not the value.
func ParseDuration(key string, defaultVal time.Duration) (time.Duration, error) {
	val, ok := os.LookupEnv(key)
	if !ok || val == "" {
		return defaultVal, nil
	}
	parsed, err := time.ParseDuration(val)
	if err != nil {
		return 0, fmt.Errorf("%s is not a valid duration", key)
	}
	return parsed, nil
}

// GetEnvOptionalString returns a pointer to the value of the environment variable
// identified by key, or nil if the variable is empty or unset.
func GetEnvOptionalString(key string) *string {
	val := os.Getenv(key)
	if val == "" {
		return nil
	}
	return &val
}

// EnvLevel represents the deployment level of a service.
// Container image builds bake in EnvLevelProduction; local development
// defaults to EnvLevelDevelopment when ENV_LEVEL is unset.
type EnvLevel string

const (
	EnvLevelProduction  EnvLevel = "production"
	EnvLevelDevelopment EnvLevel = "development"
)

// IsDev reports whether the deployment level is development.
// Strict match: unknown values return false, so production-like
// defaults apply when ENV_LEVEL is set to something unexpected.
func (l EnvLevel) IsDev() bool {
	return l == EnvLevelDevelopment
}
