package server

import (
	"context"
	"net/http"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// maxSessionsPerClient caps the live MCP sessions one token can hold. Each
// session pins memory (SDK state, a goroutine set, buffered streams) until
// DELETE or the idle timeout, and the VPS is small and shared; without a cap
// a token within its rate limit could hold about 1,800 sessions (60 a minute
// for 30 idle minutes). Normal clients use 1-2, so 16 leaves room for
// restarts and several assistants sharing one token.
const maxSessionsPerClient = 16

// sessionRetryAfter is the Retry-After, in seconds, on a refused session. A
// slot frees as soon as a client sends DELETE, or after the idle timeout.
const sessionRetryAfter = "60"

// sessionIDHeader is the MCP session header (the SDK does not export it).
const sessionIDHeader = "Mcp-Session-Id"

// sessionLimiter counts live sessions per token row (TokenInfo.UserID).
//
// The SDK has no session lifecycle hook, so the count is tied to the
// session's own lifetime: a POST without Mcp-Session-Id is the only request
// that makes the SDK create a session, so it reserves a slot before the SDK
// runs. The server factory records which *mcp.Server the SDK used for that
// request (the cache rebuilds every few seconds, so sessions live on several
// servers). Afterwards the new session is looked up by the Mcp-Session-Id
// response header in that server's Sessions(), and the slot is released when
// ServerSession.Wait returns: Wait ends however the session ends (DELETE,
// idle timeout, failed initialization). A request that leaves no live session
// releases its slot at once. Counts live in memory and end with the process.
type sessionLimiter struct {
	max  int
	mu   sync.Mutex
	live map[string]int // token row id -> live sessions; zero entries removed
}

func newSessionLimiter(limit int) *sessionLimiter {
	return &sessionLimiter{max: limit, live: map[string]int{}}
}

type newSessionKey struct{}

// newSession rides in the context of a request that may create a session.
// The SDK calls the server factory synchronously in the request goroutine,
// so the field needs no lock.
type newSession struct{ server *mcp.Server }

func (l *sessionLimiter) acquire(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.live[key] >= l.max {
		return false
	}
	l.live[key]++
	return true
}

func (l *sessionLimiter) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.live[key]--; l.live[key] <= 0 {
		delete(l.live, key) // keeps the map bounded by tokens with live sessions
	}
}

// servers wraps the server factory to record, for a request that may create
// a session, the server the SDK will connect it to. The SDK may call the
// factory more than once per request; the last call is the one it uses.
func (l *sessionLimiter) servers(get func(*http.Request) *mcp.Server) func(*http.Request) *mcp.Server {
	return func(r *http.Request) *mcp.Server {
		s := get(r)
		if ns, ok := r.Context().Value(newSessionKey{}).(*newSession); ok {
			ns.server = s
		}
		return s
	}
}

// limit refuses, with 429, a request that would open a session beyond the
// cap. Requests on an existing session pass untouched, so open sessions keep
// working at the cap.
func (l *sessionLimiter) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get(sessionIDHeader) != "" {
			next.ServeHTTP(w, r)
			return
		}
		ti := auth.TokenInfoFromContext(r.Context())
		if ti == nil || ti.UserID == "" { // unreachable behind requireToken; fail closed
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		key := ti.UserID
		if !l.acquire(key) {
			w.Header().Set("Retry-After", sessionRetryAfter)
			http.Error(w, "too many sessions", http.StatusTooManyRequests)
			return
		}
		held := true
		defer func() { // also on panic, so a slot is never lost
			if held {
				l.release(key)
			}
		}()
		ns := &newSession{}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), newSessionKey{}, ns)))
		ss := ns.find(w.Header().Get(sessionIDHeader))
		if ss == nil {
			return // no session, or it already closed: release now
		}
		held = false
		go func() {
			_ = ss.Wait() // the error is how the session ended, not a failure here
			l.release(key)
		}()
	})
}

// find returns the live session with this id on the recorded server, or nil.
func (ns *newSession) find(id string) *mcp.ServerSession {
	if id == "" || ns.server == nil {
		return nil
	}
	for ss := range ns.server.Sessions() {
		if ss.ID() == id {
			return ss
		}
	}
	return nil
}
