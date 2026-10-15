package rawpipe_test

import (
	"bufio"
	"errors"
	"io"
	"net/http"
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

// TestReadPreface: a line at the cap, its newline included, is read and
// what follows it left; one byte more, or a line ParsePreface refuses, is
// ErrPreface; a reader that fails first is not.
func TestReadPreface(t *testing.T) {
	const conn = "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d00"
	line := rawpipe.Preface + " " + conn + " kids=k1\n"
	r := bufio.NewReader(strings.NewReader(line + "rest"))
	if id, _, kids, err := rawpipe.ReadPreface(r); err != nil || id != conn ||
		strings.Join(kids, ",") != "k1" {
		t.Fatalf("ReadPreface = %q %v %v", id, kids, err)
	}
	if rest, _ := io.ReadAll(r); string(rest) != "rest" {
		t.Fatalf("left %q, want the bytes after the preface", rest)
	}
	// An unknown field pads the line to exactly the cap.
	prefix := rawpipe.Preface + " " + conn + " pad="
	pad := func(n int) string { return prefix + strings.Repeat("x", n-len(prefix)-1) + "\n" }
	exact := pad(rawpipe.MaxPrefaceLen)
	if _, _, _, err := rawpipe.ReadPreface(bufio.NewReader(strings.NewReader(exact))); err != nil {
		t.Fatalf("at the cap: %v", err)
	}
	for name, in := range map[string]string{
		"over the cap": pad(rawpipe.MaxPrefaceLen + 1),
		"bad preface":  rawpipe.Preface + " not-a-connector\n",
	} {
		_, _, _, err := rawpipe.ReadPreface(bufio.NewReader(strings.NewReader(in)))
		if !errors.Is(err, rawpipe.ErrPreface) {
			t.Errorf("%s: %v, want ErrPreface", name, err)
		}
	}
	_, _, _, err := rawpipe.ReadPreface(bufio.NewReader(strings.NewReader(rawpipe.Preface)))
	if !errors.Is(err, io.EOF) || errors.Is(err, rawpipe.ErrPreface) {
		t.Errorf("cut short: %v, want EOF", err)
	}
}

func TestCheckIdentity(t *testing.T) {
	const org, conn = "0b6e5a3c-1d2f-4a5b-8c7d-9e0f1a2b3c4d", "6f1c0a52-8d3e-4b7a-9c21-5e4f3a2b1d00"
	other := strings.Replace(conn, "6", "7", 1)
	tenant := "spiffe://traversal.com/tenant/" + org + "/acme"
	for san, id := range map[string]string{tenant: conn, tenant + "/connector/" + conn: conn} {
		if err := rawpipe.CheckIdentity(san, id); err != nil {
			t.Errorf("CheckIdentity(%q, %q): %v", san, id, err)
		}
	}
	for name, c := range map[string][2]string{
		"another connector's":   {tenant + "/connector/" + other, conn},
		"not a tenant":          {"spiffe://traversal.com/processor/x", conn},
		"no SAN":                {"", conn},
		"upper-case connector":  {tenant, strings.ToUpper(conn)},
		"connector ID not UUID": {tenant, "c1"},
	} {
		if err := rawpipe.CheckIdentity(c[0], c[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLabel(t *testing.T) {
	for r, want := range map[rawpipe.Reason]rawpipe.Reason{
		rawpipe.DialFailed: rawpipe.DialFailed, "made_up": rawpipe.Other, "": rawpipe.Other,
		rawpipe.Other: rawpipe.Other,
	} {
		if got := r.Label(); got != want {
			t.Errorf("%q.Label() = %q, want %q", r, got, want)
		}
	}
}

func TestIsNoTunnel(t *testing.T) {
	for r, want := range map[*rawpipe.Refusal]bool{
		{Status: http.StatusServiceUnavailable}:                           true,
		{Status: http.StatusServiceUnavailable, Reason: rawpipe.NoTunnel}: false,
		{Status: http.StatusServiceUnavailable, Reason: rawpipe.Capacity}: false,
		{Status: http.StatusBadGateway}:                                   false,
		nil:                                                               false,
	} {
		if got := rawpipe.IsNoTunnel(r); got != want {
			t.Errorf("IsNoTunnel(%+v) = %v", r, got)
		}
	}
}

// TestHeaderPeerURISAN pins the header the edge gateway's Envoy config sets,
// which lives in another repository.
func TestHeaderPeerURISAN(t *testing.T) {
	if rawpipe.HeaderPeerURISAN != "X-Traversal-Peer-Uri-San" {
		t.Fatal(rawpipe.HeaderPeerURISAN)
	}
}
