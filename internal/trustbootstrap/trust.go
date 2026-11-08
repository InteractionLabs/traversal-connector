// Package trustbootstrap pins connector trust obtained over the enrollment mTLS channel.
package trustbootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
)

const maxDocumentBytes = 1024 * 1024

// Document is the trust material pinned together at enrollment.
type Document struct {
	SchemaVersion   int    `json:"schema_version"`
	CapabilityRoots string `json:"capability_roots_pem"`
	ConfigKeys      string `json:"config_keys_pem"`
}

// Result is validated trust ready for the existing capability and config verifiers.
type Result struct {
	CapabilityRoots  string
	ConfigKeys       string
	RootFingerprints []string
	Created          bool
}

// LoadOrEnroll loads an existing pin or fetches and atomically creates it once.
// It never replaces an existing file; an operator must remove it to re-enroll.
func LoadOrEnroll(ctx context.Context, client *http.Client, endpoint, path string) (Result, error) {
	if path == "" {
		return Result{}, errors.New("trust bootstrap requires a state file")
	}
	if data, err := os.ReadFile(path); err == nil {
		return parse(data, false)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Result{}, fmt.Errorf("read pinned trust: %w", err)
	}
	if client == nil || endpoint == "" {
		return Result{}, errors.New("trust bootstrap requires an HTTP client and endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Result{}, errors.New("create trust bootstrap request")
	}
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("fetch enrollment trust: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("fetch enrollment trust: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes+1))
	if err != nil {
		return Result{}, errors.New("read enrollment trust response")
	}
	if len(data) > maxDocumentBytes {
		return Result{}, errors.New("enrollment trust response exceeds 1 MiB")
	}
	result, err := parse(data, true)
	if err != nil {
		return Result{}, err
	}
	if err := persistExclusive(path, data); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return Result{}, err
		}
		pinned, readErr := os.ReadFile(path)
		if readErr != nil {
			return Result{}, fmt.Errorf("read concurrently pinned trust: %w", readErr)
		}
		return parse(pinned, false)
	}
	result.Created = true
	return result, nil
}

func parse(data []byte, fetched bool) (Result, error) {
	var doc Document
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return Result{}, errors.New("invalid trust bootstrap document")
	}
	if dec.Decode(&struct{}{}) != io.EOF || doc.SchemaVersion != 1 {
		return Result{}, errors.New("trust bootstrap document requires schema_version 1 and no trailing data")
	}
	roots, err := capability.ParseRootsPEM([]byte(doc.CapabilityRoots))
	if err != nil {
		return Result{}, fmt.Errorf("trust bootstrap capability roots: %w", err)
	}
	if _, err := capability.ParseKeys([]byte(doc.ConfigKeys)); err != nil {
		return Result{}, fmt.Errorf("trust bootstrap config keys: %w", err)
	}
	fingerprints := make([]string, 0, len(roots))
	for _, root := range roots {
		sum := sha256.Sum256(root.Raw)
		fingerprints = append(fingerprints, hex.EncodeToString(sum[:]))
	}
	return Result{CapabilityRoots: doc.CapabilityRoots, ConfigKeys: doc.ConfigKeys,
		RootFingerprints: fingerprints, Created: fetched}, nil
}

func persistExclusive(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create trust state directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create pinned trust: %w", err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err = file.Write(data); err != nil {
		return fmt.Errorf("write pinned trust: %w", err)
	}
	if err = file.Sync(); err != nil {
		return fmt.Errorf("sync pinned trust: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close pinned trust: %w", err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open trust state directory: %w", err)
	}
	defer directory.Close()
	if err = directory.Sync(); err != nil {
		return fmt.Errorf("sync trust state directory: %w", err)
	}
	ok = true
	return nil
}
