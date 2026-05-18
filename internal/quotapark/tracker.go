package quotapark

import (
	"sync"
	"time"
)

// tracker maintains an in-memory ring buffer of recent 429 timestamps per
// authID and decides when the configured threshold is exceeded.
//
// Concurrency: all methods are safe for concurrent use. The mutex is internal
// and not exported; do not acquire any external lock while holding it.
type tracker struct {
	mu        sync.Mutex
	hits      map[string][]time.Time
	graceTill map[string]time.Time
	window    time.Duration
	count     int
	grace     time.Duration
}

func newTracker(window, grace time.Duration, count int) *tracker {
	if window <= 0 {
		window = 3 * time.Minute
	}
	if count <= 0 {
		count = 2
	}
	if grace < 0 {
		grace = 0
	}
	return &tracker{
		hits:      make(map[string][]time.Time),
		graceTill: make(map[string]time.Time),
		window:    window,
		count:     count,
		grace:     grace,
	}
}

// Reconfigure swaps the rolling parameters. Existing ring buffers are kept;
// the next Observe call will prune anything outside the new window.
func (t *tracker) Reconfigure(window, grace time.Duration, count int) {
	if window <= 0 {
		window = 3 * time.Minute
	}
	if count <= 0 {
		count = 2
	}
	if grace < 0 {
		grace = 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.window = window
	t.count = count
	t.grace = grace
}

// Observe429 records a 429 timestamp for authID and returns true if the count
// inside the rolling window has reached the threshold. Returning true is the
// caller's signal to park the auth. While the post-unpark grace window is
// active for authID, all 429 hits are silently dropped.
func (t *tracker) Observe429(authID string, at time.Time) bool {
	if authID == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if grace, ok := t.graceTill[authID]; ok {
		if at.Before(grace) {
			return false
		}
		delete(t.graceTill, authID)
	}

	cutoff := at.Add(-t.window)
	buf := t.hits[authID]
	// Drop entries outside the window.
	kept := buf[:0]
	for _, ts := range buf {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, at)
	t.hits[authID] = kept
	return len(kept) >= t.count
}

// Reset drops all recorded hits for authID. Called when an auth completes a
// successful request, signaling the account is currently healthy.
func (t *tracker) Reset(authID string) {
	if authID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.hits, authID)
}

// StartGrace marks authID as freshly unparked. 429 hits during the next
// configured grace window are ignored to prevent immediate re-park flapping.
func (t *tracker) StartGrace(authID string, at time.Time) {
	if authID == "" || t.grace <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.graceTill[authID] = at.Add(t.grace)
	delete(t.hits, authID)
}

// hitCount returns the number of hits currently recorded for authID (used by
// tests; the live decision is made inside Observe429).
func (t *tracker) hitCount(authID string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.hits[authID])
}
