package rawpipe_test

import (
	"strings"
	"testing"

	"github.com/InteractionLabs/traversal-connector/connector-lib/rawpipe"
)

func TestTenantID(t *testing.T) {
	const org, conn = "0b6e5a3c-1d2f-4a5b-8c7d-9e0f1a2b3c4d", "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d00"
	for uri, want := range map[string][2]string{
		"spiffe://traversal.com/tenant/" + org + "/acme":                   {org, ""},
		"spiffe://traversal.com/tenant/" + org + "/acme/connector/" + conn: {org, conn},
	} {
		if o, c, ok := rawpipe.TenantID(uri); !ok || o != want[0] || c != want[1] {
			t.Errorf("TenantID(%q) = %q %q %v", uri, o, c, ok)
		}
	}
	for _, uri := range []string{"spiffe://traversal.com/processor/x", "spiffe://traversal.com/tenant/ORG/acme", ""} {
		if _, _, ok := rawpipe.TenantID(uri); ok {
			t.Errorf("TenantID(%q) accepted", uri)
		}
	}
	if rawpipe.IsConnectorID(strings.ToUpper(conn)) || !rawpipe.IsConnectorID(conn) {
		t.Error("IsConnectorID")
	}
}
