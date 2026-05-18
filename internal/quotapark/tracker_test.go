package quotapark

import (
	"testing"
	"time"
)

func TestTrackerObserve429TriggersAtThreshold(t *testing.T) {
	trk := newTracker(3*time.Minute, 0, 2)
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	if trk.Observe429("auth-a", t0) {
		t.Fatalf("1st hit must not trigger")
	}
	if !trk.Observe429("auth-a", t0.Add(30*time.Second)) {
		t.Fatalf("2nd hit within window must trigger")
	}
}

func TestTrackerObserve429PrunesOutsideWindow(t *testing.T) {
	trk := newTracker(1*time.Minute, 0, 2)
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	if trk.Observe429("auth-a", t0) {
		t.Fatalf("1st hit must not trigger")
	}
	// Second hit happens 90s later, outside the 60s window.
	if trk.Observe429("auth-a", t0.Add(90*time.Second)) {
		t.Fatalf("hit outside window must not trigger; first hit should have been pruned")
	}
	if got := trk.hitCount("auth-a"); got != 1 {
		t.Fatalf("hitCount after prune = %d, want 1", got)
	}
}

func TestTrackerReset(t *testing.T) {
	trk := newTracker(3*time.Minute, 0, 2)
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	trk.Observe429("auth-a", t0)
	trk.Reset("auth-a")
	if got := trk.hitCount("auth-a"); got != 0 {
		t.Fatalf("after Reset hitCount = %d, want 0", got)
	}
	// First post-reset hit must not trigger.
	if trk.Observe429("auth-a", t0.Add(10*time.Second)) {
		t.Fatalf("post-reset 1st hit must not trigger")
	}
}

func TestTrackerStartGraceSuppressesHits(t *testing.T) {
	trk := newTracker(3*time.Minute, 30*time.Second, 2)
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	trk.StartGrace("auth-a", t0)

	if trk.Observe429("auth-a", t0.Add(10*time.Second)) {
		t.Fatalf("hit inside grace must not trigger")
	}
	if trk.Observe429("auth-a", t0.Add(20*time.Second)) {
		t.Fatalf("hit inside grace must not trigger")
	}
	if got := trk.hitCount("auth-a"); got != 0 {
		t.Fatalf("grace must drop hits, got count=%d", got)
	}
	// After grace expires, hits resume.
	if trk.Observe429("auth-a", t0.Add(40*time.Second)) {
		t.Fatalf("1st hit after grace must not trigger")
	}
	if !trk.Observe429("auth-a", t0.Add(45*time.Second)) {
		t.Fatalf("2nd hit after grace must trigger")
	}
}

func TestTrackerReconfigureUpdatesThreshold(t *testing.T) {
	trk := newTracker(3*time.Minute, 0, 5)
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	trk.Observe429("auth-a", t0)
	trk.Observe429("auth-a", t0.Add(1*time.Second))

	trk.Reconfigure(3*time.Minute, 0, 2)
	// The accumulated 2 hits should now meet the lower threshold on the next hit
	// only if the next hit causes count >= 2 (it should already be >= 2 with 2 entries,
	// but Observe429 always appends a new hit before comparing).
	if !trk.Observe429("auth-a", t0.Add(2*time.Second)) {
		t.Fatalf("with new count=2, 3rd hit must trigger")
	}
}
