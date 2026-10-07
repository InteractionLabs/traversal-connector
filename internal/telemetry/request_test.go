package telemetry

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/InteractionLabs/traversal-connector/connector-lib/gen/connector/v1"
)

// attrMap flattens LogAttrs into key -> rendered value.
func attrMap(t *testing.T, attrs []any) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, a := range attrs {
		attr, ok := a.(slog.Attr)
		if !ok {
			t.Fatalf("LogAttrs returned %T, want slog.Attr", a)
		}
		out[attr.Key] = attr.Value.String()
	}
	return out
}

func attrKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func grafanaRequest() *pb.HttpRequest {
	return &pb.HttpRequest{
		Method: "POST",
		Url: "https://admin:hunter2@grafana.example.com/api/ds/query" +
			"?ds_type=prometheus&requestId=Q101&from=now-1h",
		Headers: []*pb.Header{{Key: "Authorization", Value: "Bearer secret-token"}},
		Body:    []byte(`{"queries":[{"expr":"sum(rate(http_requests_total[5m]))"}]}`),
	}
}

func TestParseRequestDetailLevel(t *testing.T) {
	tests := []struct {
		raw    string
		want   RequestDetailLevel
		wantOK bool
	}{
		{"", RequestDetailsOff, true},
		{"off", RequestDetailsOff, true},
		{"path", RequestDetailsPath, true},
		{"Full", RequestDetailsFull, true},
		{" path\n", RequestDetailsPath, true},
		{"query", RequestDetailsOff, false},
		{"true", RequestDetailsOff, false},
	}
	for _, tt := range tests {
		got, ok := ParseRequestDetailLevel(tt.raw)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("ParseRequestDetailLevel(%q) = (%q, %v), want (%q, %v)",
				tt.raw, got, ok, tt.want, tt.wantOK)
		}
	}
}

func TestDescribe_OffCarriesOnlyAlwaysOnFields(t *testing.T) {
	policy := NewRequestLogPolicy(RequestDetailsOff, 2048, 60*time.Second, nil)
	got := attrMap(t, policy.Describe("req-1", grafanaRequest()).LogAttrs())

	want := map[string]string{
		LogKeyRequestID:       "req-1",
		LogKeyMethod:          "POST",
		LogKeyRequestBodySize: fmt.Sprint(len(grafanaRequest().Body)),
		LogKeyTimeoutSeconds:  "60",
	}
	if !slices.Equal(attrKeys(got), attrKeys(want)) {
		t.Fatalf("keys = %v, want %v", attrKeys(got), attrKeys(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if attrs := policy.Describe("req-1", grafanaRequest()).SpanAttrs(); len(attrs) != 0 {
		t.Errorf("SpanAttrs at off = %v, want none", attrs)
	}
}

func TestDescribe_ZeroPolicyIsOff(t *testing.T) {
	var policy RequestLogPolicy
	got := attrMap(t, policy.Describe("", grafanaRequest()).LogAttrs())
	if want := []string{LogKeyMethod, LogKeyRequestBodySize}; !slices.Equal(attrKeys(got), want) {
		t.Errorf("keys = %v, want %v", attrKeys(got), want)
	}
}

func TestDescribe_PathCarriesPathAndSortedKeysOnly(t *testing.T) {
	policy := NewRequestLogPolicy(RequestDetailsPath, 2048, 0, nil)
	details := policy.Describe("req-1", grafanaRequest())
	got := attrMap(t, details.LogAttrs())

	if got[LogKeyTargetPath] != "/api/ds/query" {
		t.Errorf("target_path = %q", got[LogKeyTargetPath])
	}
	if got[LogKeyQueryKeys] != "[ds_type from requestId]" {
		t.Errorf("query_keys = %q, want sorted names", got[LogKeyQueryKeys])
	}
	for _, key := range []string{LogKeyTargetQuery, LogKeyRequestBodyExcerpt, LogKeyTimeoutSeconds} {
		if _, ok := got[key]; ok {
			t.Errorf("%s present at path level", key)
		}
	}
	all := fmt.Sprint(got)
	for _, leaked := range []string{"Q101", "now-1h", "prometheus", "hunter2", "admin", "secret-token", "rate("} {
		if strings.Contains(all, leaked) {
			t.Errorf("path level leaks %q: %s", leaked, all)
		}
	}

	spanKeys := []string{}
	for _, kv := range details.SpanAttrs() {
		spanKeys = append(spanKeys, string(kv.Key))
	}
	if want := []string{LogKeyTargetPath, LogKeyQueryKeys}; !slices.Equal(spanKeys, want) {
		t.Errorf("span keys = %v, want %v", spanKeys, want)
	}
}

func TestDescribe_FullCarriesQueryAndBody(t *testing.T) {
	policy := NewRequestLogPolicy(RequestDetailsFull, 2048, 0, nil)
	got := attrMap(t, policy.Describe("req-1", grafanaRequest()).LogAttrs())

	if got[LogKeyTargetQuery] != "ds_type=prometheus&requestId=Q101&from=now-1h" {
		t.Errorf("target_query = %q", got[LogKeyTargetQuery])
	}
	if got[LogKeyRequestBodyExcerpt] != string(grafanaRequest().Body) {
		t.Errorf("request_body_excerpt = %q", got[LogKeyRequestBodyExcerpt])
	}
	all := fmt.Sprint(got)
	for _, leaked := range []string{"hunter2", "admin", "secret-token", "Authorization"} {
		if strings.Contains(all, leaked) {
			t.Errorf("full level leaks %q: %s", leaked, all)
		}
	}
}

func TestDescribe_StripsUserinfo(t *testing.T) {
	policy := NewRequestLogPolicy(RequestDetailsFull, 2048, 0, nil)
	//nolint:gosec // G101: test fixture, intentional userinfo
	req := &pb.HttpRequest{Method: "GET", Url: "https://user:p%40ss@example.com/a?b=c"}
	all := fmt.Sprint(attrMap(t, policy.Describe("r", req).LogAttrs()))
	if strings.Contains(all, "user") || strings.Contains(all, "p%40ss") ||
		strings.Contains(all, "p@ss") {
		t.Errorf("userinfo leaked: %s", all)
	}
}

func TestDescribe_Truncates(t *testing.T) {
	policy := NewRequestLogPolicy(RequestDetailsFull, 16, 0, nil)
	longPath := "/" + strings.Repeat("p", 2000)
	longQuery := "q=" + strings.Repeat("v", 10000)
	req := &pb.HttpRequest{
		Method: "POST",
		Url:    "https://example.com" + longPath + "?" + longQuery,
		Body:   []byte(strings.Repeat("b", 100)),
	}
	got := attrMap(t, policy.Describe("r", req).LogAttrs())

	marker := regexp.MustCompile(`\.\.\.<truncated, (\d+) bytes total>$`)
	checks := []struct {
		key   string
		limit int
		total int
	}{
		{LogKeyTargetPath, maxLoggedPathBytes, len(longPath)},
		{LogKeyTargetQuery, maxLoggedQueryBytes, len(longQuery)},
		{LogKeyRequestBodyExcerpt, 16, 100},
	}
	for _, c := range checks {
		v := got[c.key]
		m := marker.FindStringSubmatch(v)
		if m == nil || m[1] != fmt.Sprint(c.total) {
			t.Errorf("%s = %q, want truncation marker naming %d bytes", c.key, v, c.total)
			continue
		}
		if kept := len(v) - len(m[0]); kept > c.limit {
			t.Errorf("%s kept %d bytes, limit %d", c.key, kept, c.limit)
		}
	}
}

func TestDescribe_TruncationKeepsValidUTF8(t *testing.T) {
	policy := NewRequestLogPolicy(RequestDetailsFull, 5, 0, nil)
	// "é" is two bytes, so a 5-byte cut lands inside the third one.
	req := &pb.HttpRequest{Method: "POST", Url: "https://example.com/", Body: []byte("ééééé")}
	got := attrMap(t, policy.Describe("r", req).LogAttrs())[LogKeyRequestBodyExcerpt]
	if !strings.HasPrefix(got, "éé...<truncated") {
		t.Errorf("excerpt = %q, want a cut on a rune boundary", got)
	}
}

func TestDescribe_BinaryBodyGetsMarker(t *testing.T) {
	policy := NewRequestLogPolicy(RequestDetailsFull, 2048, 0, nil)
	for name, body := range map[string][]byte{
		"invalid utf-8": {0xff, 0xfe, 0x00, 0x01, 'a'},
		"control bytes": []byte("snappy\x00\x01\x02"),
	} {
		req := &pb.HttpRequest{Method: "POST", Url: "https://example.com/api/v1/read", Body: body}
		got := attrMap(t, policy.Describe("r", req).LogAttrs())[LogKeyRequestBodyExcerpt]
		if want := fmt.Sprintf("<binary %d bytes>", len(body)); got != want {
			t.Errorf("%s: excerpt = %q, want %q", name, got, want)
		}
	}
}

func TestDescribe_ZeroBodyMaxBytesOmitsExcerpt(t *testing.T) {
	policy := NewRequestLogPolicy(RequestDetailsFull, 0, 0, nil)
	got := attrMap(t, policy.Describe("r", grafanaRequest()).LogAttrs())
	if _, ok := got[LogKeyRequestBodyExcerpt]; ok {
		t.Error("excerpt present with LOG_REQUEST_BODY_MAX_BYTES=0")
	}
	if _, ok := got[LogKeyTargetQuery]; !ok {
		t.Error("target_query missing at full level")
	}
}

func TestDescribe_QueryKeysAreDeduplicatedAndBounded(t *testing.T) {
	policy := NewRequestLogPolicy(RequestDetailsPath, 0, 0, nil)
	var query []string
	for i := range maxLoggedQueryKeys + 10 {
		query = append(query, fmt.Sprintf("k%03d=1", i), fmt.Sprintf("k%03d=2", i))
	}
	req := &pb.HttpRequest{Method: "GET", Url: "https://example.com/?" + strings.Join(query, "&")}
	keys := policy.Describe("r", req).SpanAttrs()[1].Value.AsStringSlice()
	if len(keys) != maxLoggedQueryKeys+1 || keys[len(keys)-1] != "<10 more>" {
		t.Errorf("query keys = %d entries ending %q", len(keys), keys[len(keys)-1])
	}
}

func TestDescribe_ScrubAppliesToPathQueryAndBody(t *testing.T) {
	var hosts []string
	scrub := func(host string, text []byte) []byte {
		hosts = append(hosts, host)
		return bytes.ReplaceAll(text, []byte("SECRET"), []byte("[REDACTED]"))
	}
	policy := NewRequestLogPolicy(RequestDetailsFull, 2048, 0, scrub)
	req := &pb.HttpRequest{
		Method: "POST",
		Url:    "https://grafana.example.com:3000/u/SECRET?token=SECRET",
		Body:   []byte(`{"key":"SECRET"}`),
	}
	all := fmt.Sprint(attrMap(t, policy.Describe("r", req).LogAttrs()))
	if strings.Contains(all, "SECRET") {
		t.Errorf("scrub not applied: %s", all)
	}
	for _, h := range hosts {
		if h != "grafana.example.com" {
			t.Errorf("scrub called with host %q, want hostname without port", h)
		}
	}
}

func TestDescribe_UnparseableURL(t *testing.T) {
	policy := NewRequestLogPolicy(RequestDetailsFull, 2048, 0, nil)
	req := &pb.HttpRequest{Method: "GET", Url: "http://h/\x7f?token=canary"}
	got := attrMap(t, policy.Describe("r", req).LogAttrs())
	if got[LogKeyTargetPath] != unknownPath {
		t.Errorf("target_path = %q, want %q", got[LogKeyTargetPath], unknownPath)
	}
	if strings.Contains(fmt.Sprint(got), "canary") {
		t.Errorf("unparseable URL leaked: %v", got)
	}
}

func TestRequestIDContext(t *testing.T) {
	if got := RequestIDFromContext(context.Background()); got != "" {
		t.Errorf("empty context id = %q", got)
	}
	ctx := ContextWithRequestID(context.Background(), "req-9")
	if got := RequestIDFromContext(ctx); got != "req-9" {
		t.Errorf("id = %q, want req-9", got)
	}
}
