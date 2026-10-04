package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JoseJimenez-M/cortex-mcp/internal/config"
)

// refusals returns the "request refused" records in the JSON log.
func refusals(t *testing.T, buf *syncBuffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", l)
		}
		if m["msg"] == "request refused" {
			out = append(out, m)
		}
	}
	return out
}

func TestRateLimitRefusalIsLoggedOncePerMinute(t *testing.T) {
	var buf syncBuffer
	e := setupOpts(t, func(c *config.Config) { c.Limits.RequestsPerMinute = 6 }, withLogger(&buf)) // burst 1
	post(t, e.url, "Bearer "+e.secret)
	for range 3 {
		if code := post(t, e.url, "Bearer "+e.secret); code != http.StatusTooManyRequests {
			t.Fatalf("status %d, want 429", code)
		}
	}
	got := refusals(t, &buf)
	if len(got) != 1 {
		t.Fatalf("three refusals within a minute: %d log lines, want 1:\n%s", len(got), buf.String())
	}
	r := got[0]
	if r["level"] != "WARN" || r["limit"] != "rate" || r["client"] != "test-client" || r["retry_after_s"] != "10" || r["suppressed"] != float64(0) {
		t.Fatalf("record = %v", r)
	}

	e.clock.Advance(time.Minute)
	time.Sleep(10 * time.Second / 6) // let the 6/min bucket hold one token again
	post(t, e.url, "Bearer "+e.secret)
	post(t, e.url, "Bearer "+e.secret)
	got = refusals(t, &buf)
	if len(got) != 2 || got[1]["suppressed"] != float64(2) {
		t.Fatalf("after a minute: %v, want a second record counting the 2 unlogged refusals", got)
	}
	if strings.Contains(buf.String(), e.secret) || strings.Contains(buf.String(), "Bearer") {
		t.Fatal("log leaks the token or the Authorization scheme") // never print the buffer: it would hold the secret
	}
}

func TestSessionCapRefusalIsLogged(t *testing.T) {
	var buf syncBuffer
	e := setupOpts(t, func(c *config.Config) {
		manySessions(c)
		c.Limits.MaxSessionsPerClient = 1
	}, withLogger(&buf))
	other, err := e.store.Create("other-client")
	if err != nil {
		t.Fatal(err)
	}
	rawInit(t, e, e.secret)
	rawInit(t, e, other)
	if code, _, _, _ := rawInit(t, e, e.secret); code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", code)
	}
	if code, _, _, _ := rawInit(t, e, other); code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", code)
	}
	got := refusals(t, &buf)
	if len(got) != 2 {
		t.Fatalf("one refusal per client: %d records, want 2:\n%s", len(got), buf.String())
	}
	for i, want := range []string{"test-client", "other-client"} {
		if got[i]["limit"] != "sessions" || got[i]["client"] != want || got[i]["retry_after_s"] != "60" {
			t.Fatalf("record %d = %v", i, got[i])
		}
	}
}
