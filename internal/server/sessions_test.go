package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/JoseJimenez-M/cortex-mcp/internal/config"
)

const initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",` +
	`"capabilities":{},"clientInfo":{"name":"raw","version":"0"}}}`

// testCap is a small session cap, so tests reach it quickly.
const testCap = 4

// manySessions lifts the rate limit so a test can open many sessions in a
// row, and sets the session cap to testCap.
func manySessions(c *config.Config) {
	c.Limits.RequestsPerMinute = 60000
	c.Limits.MaxSessionsPerClient = testCap
}

func tryConnect(e env, token string) (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "it", Version: "test"}, nil)
	return client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   e.url + "/mcp",
		HTTPClient: &http.Client{Transport: bearer{token, http.DefaultTransport}},
	}, nil)
}

// rawInit sends an initialize without a session id and returns the status,
// the body, the Retry-After header and the new session id, if any. A created
// session is deleted when the test ends.
func rawInit(t *testing.T, e env, token string) (code int, body, retry, sid string) {
	t.Helper()
	resp := doPost(t, e.url, "Bearer "+token, initBody)
	b, _ := io.ReadAll(resp.Body)
	sid = resp.Header.Get("Mcp-Session-Id")
	if sid != "" {
		t.Cleanup(func() { deleteSession(t, e, token, sid) })
	}
	return resp.StatusCode, string(b), resp.Header.Get("Retry-After"), sid
}

func deleteSession(t *testing.T, e env, token, sid string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, e.url+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
		return
	}
	_ = resp.Body.Close()
}

// eventuallyConnects retries until a session opens: a slot is released when
// the SDK finishes closing the old session, just after DELETE returns.
func eventuallyConnects(t *testing.T, e env, token string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		cs, err := tryConnect(e, token)
		if err == nil {
			_ = cs.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no session slot freed within %s: %v", within, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSessionCapPerToken(t *testing.T) {
	e := setup(t, manySessions)
	other, err := e.store.Create("other-client")
	if err != nil {
		t.Fatal(err)
	}
	var open []*mcp.ClientSession
	for i := range testCap {
		if i%2 == 0 { // spread the sessions over several cached servers
			e.clock.Advance(instructionsTTL + time.Second)
		}
		open = append(open, connect(t, e, e.secret))
	}
	code, body, retry, sid := rawInit(t, e, e.secret)
	if code != http.StatusTooManyRequests || sid != "" {
		t.Fatalf("session %d: status %d, session %q; want 429 and none", testCap+1, code, sid)
	}
	if retry == "" || strings.TrimSpace(body) != "too many sessions" {
		t.Fatalf("429 must carry Retry-After and a fixed body: %q %q", retry, body)
	}
	for i, cs := range open {
		if err := cs.Ping(context.Background(), nil); err != nil {
			t.Fatalf("existing session %d stopped working at the cap: %v", i, err)
		}
	}
	connect(t, e, other) // another token's budget is untouched

	if err := open[0].Close(); err != nil { // DELETE, on the oldest server
		t.Fatal(err)
	}
	eventuallyConnects(t, e, e.secret, 5*time.Second)
}

func TestIdleSessionsFreeTheirSlot(t *testing.T) {
	const idle = 2 * time.Second
	e := setupOpts(t, manySessions, func(o *Options) { o.idleTimeout = idle })
	start := time.Now()
	for range testCap {
		connect(t, e, e.secret)
	}
	code, _, _, _ := rawInit(t, e, e.secret)
	if time.Since(start) < idle && code != http.StatusTooManyRequests {
		t.Fatalf("at the cap: status %d, want 429", code)
	}
	eventuallyConnects(t, e, e.secret, idle+5*time.Second)
}

func TestSessionCapHoldsUnderConcurrency(t *testing.T) {
	e := setup(t, manySessions)
	const n = 2 * testCap
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			code, _, _, _ := rawInit(t, e, e.secret)
			codes <- code
		})
	}
	wg.Wait()
	close(codes)
	ok, limited := 0, 0
	for c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Errorf("unexpected status %d", c)
		}
	}
	if ok != testCap || limited != n-testCap {
		t.Fatalf("%d sessions opened, %d refused; want %d and %d", ok, limited, testCap, n-testCap)
	}
}

func TestRequestsWithoutSessionThatFailDoNotHoldASlot(t *testing.T) {
	e := setup(t, manySessions)
	// A ping without a session id makes the SDK open a session and close it
	// again at once, because it was never initialized.
	for range 2 * testCap {
		post(t, e.url, "Bearer "+e.secret)
	}
	eventuallyConnects(t, e, e.secret, 5*time.Second)
}

func TestSessionCapFollowsConfig(t *testing.T) {
	e := setup(t, func(c *config.Config) {
		manySessions(c)
		c.Limits.MaxSessionsPerClient = 2
	})
	for i := range 2 {
		if code, _, _, _ := rawInit(t, e, e.secret); code != http.StatusOK {
			t.Fatalf("session %d: %d, want 200", i+1, code)
		}
	}
	if code, _, _, _ := rawInit(t, e, e.secret); code != http.StatusTooManyRequests {
		t.Fatalf("session 3 with a cap of 2: %d, want 429", code)
	}
}
