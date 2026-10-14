package rawpipe_test

import (
	"io"
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
	for _, uri := range []string{
		"spiffe://traversal.com/processor/x",
		"spiffe://traversal.com/tenant/ORG/acme",
		"",
	} {
		if _, _, ok := rawpipe.TenantID(uri); ok {
			t.Errorf("TenantID(%q) accepted", uri)
		}
	}
	if rawpipe.IsConnectorID(strings.ToUpper(conn)) || !rawpipe.IsConnectorID(conn) {
		t.Error("IsConnectorID")
	}
}

func TestKnown(t *testing.T) {
	known := map[rawpipe.Reason]bool{rawpipe.DialFailed: true, "made_up": false, "": false}
	for r, want := range known {
		if r.Known() != want {
			t.Errorf("%q.Known() = %v", r, !want)
		}
	}
}

func TestPreface(t *testing.T) {
	const conn = "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d00"
	root := rawpipe.RootFingerprint([]byte("root DER"))
	if len(root) != 16 {
		t.Fatalf("fingerprint %q", root)
	}
	for _, c := range []struct {
		roots, kids []string
		want        string
	}{
		{nil, nil, rawpipe.Preface + " " + conn + "\n"},
		{[]string{root}, nil, rawpipe.Preface + " " + conn + " roots=" + root + "\n"},
		{[]string{root, "0123456789abcdef"}, []string{"k1", "k2"}, rawpipe.Preface + " " + conn +
			" roots=" + root + ",0123456789abcdef kids=k1,k2\n"},
	} {
		var b strings.Builder
		if err := rawpipe.WritePreface(&b, conn, c.roots, c.kids); err != nil ||
			b.String() != c.want {
			t.Fatalf("WritePreface = %q, %v; want %q", b.String(), err, c.want)
		}
		id, roots, kids, ok := rawpipe.ParsePreface(b.String())
		if !ok || id != conn || strings.Join(roots, ",") != strings.Join(c.roots, ",") ||
			strings.Join(kids, ",") != strings.Join(c.kids, ",") {
			t.Fatalf("ParsePreface(%q) = %q %v %v %v", b.String(), id, roots, kids, ok)
		}
	}
	for name, kids := range map[string][]string{
		"empty kid": {""}, "comma": {"a,b"}, "space": {"a b"}, "long": {strings.Repeat("k", 512)},
	} {
		if err := rawpipe.WritePreface(io.Discard, conn, nil, kids); err == nil {
			t.Errorf("WritePreface with %s: accepted", name)
		}
	}
	if err := rawpipe.WritePreface(io.Discard, strings.ToUpper(conn), nil, nil); err == nil {
		t.Error("WritePreface with an upper-case connector ID: accepted")
	}

	// Unknown fields are ignored; the tag and connector ID are strict.
	if id, _, kids, ok := rawpipe.ParsePreface(
		rawpipe.Preface + " " + conn + " future=x kids=k1\n"); !ok || id != conn ||
		len(kids) != 1 {
		t.Errorf("unknown field: %q %v %v", id, kids, ok)
	}
	for _, line := range []string{
		rawpipe.Preface + "\n",
		rawpipe.Preface + " " + strings.ToUpper(conn) + "\n",
		"TRAVERSAL-TUNNEL/2 " + conn + "\n",
		rawpipe.Preface + "  " + conn + "\n",
		rawpipe.Preface + " " + conn + " bare\n",
		rawpipe.Preface + " " + conn + " kids=a kids=b\n",
		rawpipe.Preface + " " + conn + " =x\n",
	} {
		if _, _, _, ok := rawpipe.ParsePreface(line); ok {
			t.Errorf("ParsePreface(%q) accepted", line)
		}
	}
}
