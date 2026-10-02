// validate-config checks a Connector OTA TOML document on stdin, using exactly
// the connector's parser and rule compiler. It makes no network requests.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/InteractionLabs/traversal-connector/internal/redact"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stderr))
}

func run(args []string, input io.Reader, diagnostics io.Writer) int {
	if len(args) != 0 {
		_, _ = fmt.Fprintln(diagnostics, "usage: validate-config < config.toml")
		return 2
	}
	data, err := io.ReadAll(io.LimitReader(input, redact.MaxConfigBytes+1))
	if err != nil {
		_, _ = fmt.Fprintln(diagnostics, "could not read config")
		return 1
	}
	if err = redact.ValidateConfig(data); err != nil {
		_, _ = fmt.Fprintln(diagnostics, err)
		return 1
	}
	return 0
}
