package rawclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
	"github.com/InteractionLabs/traversal-connector/connector-lib/capability/capabilitytest"
	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
	"github.com/InteractionLabs/traversal-connector/internal/redact"
)

func TestRefusalDetailOmitsResolvedAddress(t *testing.T) {
	const leaked = "10.9.8.7"
	policy := directPolicy(t,
		func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New("lookup " + leaked + ":53: no such host")
		},
		neverDial(t),
	)
	_, _, err := policy.Dial(t.Context(), "db.internal", testPort)
	detail := failureDetail(err)
	if strings.Contains(detail, leaked) || strings.Contains(detail, "db.internal") {
		t.Fatalf("detail %q includes the destination", detail)
	}
	if detail != "name did not resolve" {
		t.Fatalf("detail %q", detail)
	}
	if !strings.Contains(err.Error(), leaked) {
		t.Fatalf("local error %v dropped the address", err)
	}
}

func TestHostScopedRuleRefusesIPLiteral(t *testing.T) {
	redactor := loadRules(t, "version = \"v1\"\n[[rules]]\nname = \"email\"\n"+
		"type = \"regex\"\npattern = \"a\"\nhosts = ['db\\\\.internal']\n")
	policy, err := newPolicy(baseConfig("http://127.0.0.1:9"), redactor)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = policy.Dial(t.Context(), "10.1.2.3", testPort)
	detail := failureDetail(err)
	if strings.Contains(detail, "10.1.2.3") {
		t.Fatalf("detail %q includes the address", detail)
	}
	if detail != "destination requires inspection" {
		t.Fatalf("detail %q, err %v", detail, err)
	}
}

func TestUnscopedRuleAdvertisesBlockedRawPipes(t *testing.T) {
	redactor := loadRules(t, "version = \"v1\"\n[[rules]]\nname = \"email\"\n"+
		"type = \"regex\"\npattern = \"a\"\n")
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	cfg := baseConfig("http://127.0.0.1:9")
	m, err := newManager(cfg, redactor, nil, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !m.hello.message().GetRedactionBlocksPipes() {
		t.Fatal("hello did not say raw pipes are blocked")
	}
	if !strings.Contains(buf.String(), "no host filter") {
		t.Fatalf("log %q", buf.String())
	}
}

func TestConnectorVerifierAllowsUnknownClaim(t *testing.T) {
	payload, err := json.Marshal(testClaims("jti-extra"))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	fields["agent_id"] = json.RawMessage(`"agent-1"`)
	extra, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	header, err := json.Marshal(capability.Header{
		Algorithm: capability.Algorithm,
		KeyID:     testKid,
		Type:      capability.TokenType,
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := capabilitytest.SignRaw(testKey(), header, extra)
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := newRawMetrics()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := newVerifier(baseConfig("http://127.0.0.1:9"), metrics)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(token, capability.Expected{
		ConnectorID: "connector-1",
		Host:        testHost,
		Port:        testPort,
		Mode:        pb.RawPipeMode_RAW_PIPE_MODE_PASSTHROUGH,
	}); err != nil {
		t.Fatal(err)
	}
}

func loadRules(t *testing.T, body string) *redact.Redactor {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	redactor := redact.NewRedactor()
	if err := redact.NewFileLoader(path, redactor, time.Second).LoadInitial(); err != nil {
		t.Fatal(err)
	}
	return redactor
}
