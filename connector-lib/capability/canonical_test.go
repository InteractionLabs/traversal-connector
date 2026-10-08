package capability_test

import (
	"strings"
	"testing"

	"github.com/InteractionLabs/traversal-connector/connector-lib/capability"
)

// hostCases is the canonicalization table, shared with testdata/vectors.json.
var hostCases = []struct {
	input, canonical string // canonical is empty when input is invalid
}{
	{"db.internal", "db.internal"},
	{"DB.Internal.", "db.internal"},
	{"ＤＢ．ｉｎｔｅｒｎａｌ", "db.internal"},
	{"db。internal", "db.internal"},
	{"bücher.example", "xn--bcher-kva.example"},
	{"xn--bcher-kva.example", "xn--bcher-kva.example"},
	{"_grpc._tcp.svc.cluster.local", "_grpc._tcp.svc.cluster.local"},
	{strings.Repeat("a", 63) + ".example", strings.Repeat("a", 63) + ".example"},
	{"10.0.0.1", "10.0.0.1"},
	{"1.2.3.4.", "1.2.3.4"},
	{"１２７.０.０.１", "127.0.0.1"},
	{"::FFFF:10.0.0.1", "10.0.0.1"},
	{"2001:DB8:0:0:0:0:0:1", "2001:db8::1"},
	{"::1", "::1"},
	{"", ""},
	{".", ""},
	{"a..b", ""},
	{"db.internal..", ""},
	{"127.1", ""},
	{"0x7f.0.0.1", ""},
	{"0x7f000001", ""},
	{"2130706433", ""},
	{"010.0.0.1", ""},
	{"1.2.3", ""},
	{"example.0x10", ""},
	{"db.internal:5432", ""},
	{"[::1]", ""},
	{"fe80::1%eth0", ""},
	{"db internal", ""},
	{"db*.internal", ""},
	{"db%2e.internal", ""},
	{"db/.internal", ""},
	{"-db.internal", ""},
	{"db-.internal", ""},
	{"exa\u200dmple.internal", ""},
	{"\xc30.internal", ""},
	{strings.Repeat("a", 64) + ".example", ""},
	{strings.Repeat("a.", 126) + "ab", ""},
}

func TestCanonicalHost(t *testing.T) {
	for _, tc := range hostCases {
		got, err := capability.CanonicalHost(tc.input)
		if tc.canonical == "" {
			if err == nil {
				t.Errorf("CanonicalHost(%q) = %q, want an error", tc.input, got)
			}
			continue
		}
		if err != nil || got != tc.canonical {
			t.Errorf("CanonicalHost(%q) = %q, %v, want %q", tc.input, got, err, tc.canonical)
		}
	}
}

func TestCanonicalAuthority(t *testing.T) {
	for host, want := range map[string]string{
		"db.internal": "db.internal:5432",
		"10.0.0.1":    "10.0.0.1:5432",
		"2001:db8::1": "[2001:db8::1]:5432",
	} {
		if got := capability.CanonicalAuthority(host, 5432); got != want {
			t.Errorf("CanonicalAuthority(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestSplitAuthority(t *testing.T) {
	type split struct {
		host string
		port uint16
	}
	for _, tc := range []struct {
		authority string
		want      *split // nil when authority is invalid
	}{
		{"db.internal:5432", &split{"db.internal", 5432}},
		{"10.0.0.1:1", &split{"10.0.0.1", 1}},
		{"[2001:db8::1]:65535", &split{"2001:db8::1", 65535}},
		{"db.internal", nil},
		{"db.internal:", nil},
		{"db.internal:0", nil},
		{"db.internal:05432", nil},
		{"db.internal:+5432", nil},
		{"db.internal:65536", nil},
		{"db.internal:http", nil},
		{"DB.internal:5432", nil},
		{"db.internal.:5432", nil},
		{"[2001:DB8::1]:5432", nil},
		{"[::ffff:10.0.0.1]:5432", nil},
		{"[fe80::1%eth0]:5432", nil},
		{"2001:db8::1:5432", nil},
		{":5432", nil},
		{"[1.2.3.4]:443", nil},
		{"[db.internal]:5432", nil},
	} {
		host, port, ok := capability.SplitAuthority(tc.authority)
		if tc.want == nil {
			if ok {
				t.Errorf("SplitAuthority(%q) = %q, %d, want invalid", tc.authority, host, port)
			}
			continue
		}
		if !ok || host != tc.want.host || port != tc.want.port {
			t.Errorf("SplitAuthority(%q) = %q, %d, %v, want %q, %d",
				tc.authority, host, port, ok, tc.want.host, tc.want.port)
		}
		if got := capability.CanonicalAuthority(host, port); got != tc.authority {
			t.Errorf("CanonicalAuthority(SplitAuthority(%q)) = %q", tc.authority, got)
		}
	}
}

func TestAbsoluteHost(t *testing.T) {
	for host, want := range map[string]string{
		"db.internal": "db.internal.",
		"db":          "db.",
		"10.0.0.1":    "10.0.0.1",
		"2001:db8::1": "2001:db8::1",
	} {
		if got := capability.AbsoluteHost(host); got != want {
			t.Errorf("AbsoluteHost(%q) = %q, want %q", host, got, want)
		}
	}
}

// FuzzCanonicalHost checks that canonical hosts are fixed points, so a value a
// signer canonicalized always passes a validator's canonical check.
func FuzzCanonicalHost(f *testing.F) {
	for _, tc := range hostCases {
		f.Add(tc.input)
	}
	f.Fuzz(func(t *testing.T, host string) {
		canonical, err := capability.CanonicalHost(host)
		if err != nil {
			return
		}
		again, err := capability.CanonicalHost(canonical)
		if err != nil || again != canonical {
			t.Fatalf("CanonicalHost(%q) = %q, but that canonicalizes to %q, %v",
				host, canonical, again, err)
		}
		if len(canonical) > 253 || strings.ContainsAny(canonical, "[]%/ ") {
			t.Fatalf("CanonicalHost(%q) = %q", host, canonical)
		}
	})
}
