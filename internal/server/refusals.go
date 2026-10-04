package server

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// refusalLogEvery is how often one client's refusals by one limit are
// logged. A client that loops on 429 would otherwise write a line per
// request; the next record carries how many were left out.
const refusalLogEvery = time.Minute

// refusalLog records 429s, so the owner can tell which limit a client hit
// (rate or sessions) and tune it. It logs the client name only: never the
// token, the Authorization header, or other TokenInfo contents. The map is
// keyed on the rate key, so like the rate limiter's it is bounded by the
// names ever issued plus the grants ever approved.
type refusalLog struct {
	lg  *slog.Logger
	now func() time.Time

	mu   sync.Mutex
	seen map[refusalKey]*refusalState
}

type refusalKey struct{ limit, client string }

type refusalState struct {
	logged     time.Time
	suppressed int
}

func newRefusalLog(lg *slog.Logger, now func() time.Time) *refusalLog {
	return &refusalLog{lg: lg, now: now, seen: map[refusalKey]*refusalState{}}
}

// note records that r was refused by limit with this Retry-After.
func (l *refusalLog) note(r *http.Request, limit, retryAfter string) {
	ti := auth.TokenInfoFromContext(r.Context())
	if ti == nil {
		return
	}
	k := refusalKey{limit: limit, client: rateKey(r)}
	now := l.now()
	l.mu.Lock()
	st, ok := l.seen[k]
	if ok && now.Sub(st.logged) < refusalLogEvery {
		st.suppressed++
		l.mu.Unlock()
		return
	}
	suppressed := 0
	if ok {
		suppressed = st.suppressed
	}
	l.seen[k] = &refusalState{logged: now}
	l.mu.Unlock()
	name, _ := ti.Extra["client"].(string)
	l.lg.Warn("request refused", "limit", limit, "client", name, "retry_after_s", retryAfter, "suppressed", suppressed)
}
