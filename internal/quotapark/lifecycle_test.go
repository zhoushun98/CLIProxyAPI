package quotapark

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func newTestCfg(t *testing.T, authDir string) *config.Config {
	t.Helper()
	cfg := &config.Config{AuthDir: authDir}
	cfg.QuotaPark.Enabled = true
	cfg.QuotaPark.Directory = ".disabled"
	cfg.QuotaPark.Trigger.Window = "3m"
	cfg.QuotaPark.Trigger.Count = 2
	cfg.QuotaPark.Trigger.GraceAfterUnpark = "60s"
	cfg.QuotaPark.Probe.Interval = "5m"
	cfg.QuotaPark.Probe.Prompt = "Say hi"
	cfg.QuotaPark.Probe.MaxOutputTokens = 1
	cfg.QuotaPark.Probe.Model = "gpt-5-codex-mini"
	return cfg
}

func TestServicePerformParkIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	authID := "codex-foo.json"
	writeFile(t, filepath.Join(dir, authID), `{"type":"codex"}`)

	cfg := newTestCfg(t, dir)
	svc := New(cfg, neverProbe)

	first := svc.performPark(authID, "codex", "gpt-5.4", time.Now())
	if !first {
		t.Fatalf("first performPark must return true")
	}
	second := svc.performPark(authID, "codex", "gpt-5.4", time.Now())
	if second {
		t.Fatalf("second performPark must be no-op")
	}
}

func TestServiceObserve429ProviderFilter(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestCfg(t, dir)
	svc := New(cfg, neverProbe)

	// Non-codex providers must not enter the tracker even after many 429s.
	for i := 0; i < 10; i++ {
		if svc.observe429("auth-x", "claude", "claude-3-5", time.Now()) {
			t.Fatalf("claude provider must not park in v1 scope")
		}
	}
	if svc.IsParked("auth-x") {
		t.Fatalf("claude auth must not be parked")
	}
}

func TestServiceObserve429ParksAfterBurst(t *testing.T) {
	dir := t.TempDir()
	authID := "codex-foo.json"
	writeFile(t, filepath.Join(dir, authID), `{"type":"codex"}`)

	cfg := newTestCfg(t, dir)
	svc := New(cfg, neverProbe)

	now := time.Now()
	if svc.observe429(authID, "codex", "gpt-5.4", now) {
		t.Fatalf("1st 429 should not park")
	}
	if !svc.observe429(authID, "codex", "gpt-5.4", now.Add(time.Second)) {
		t.Fatalf("2nd 429 within window should park")
	}
	if !svc.IsParked(authID) {
		t.Fatalf("auth should be in parked state")
	}
	if _, statErr := os.Stat(filepath.Join(dir, ".disabled", authID)); statErr != nil {
		t.Fatalf("file should have been moved to .disabled: %v", statErr)
	}
}

func TestServiceRebuildFromDiskPopulatesState(t *testing.T) {
	dir := t.TempDir()
	disabled := filepath.Join(dir, ".disabled")
	if err := os.MkdirAll(disabled, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(disabled, "codex-foo.json"), `{"type":"codex"}`)
	writeFile(t, filepath.Join(disabled, "codex-bar.json"), `{"type":"codex"}`)

	cfg := newTestCfg(t, dir)
	svc := New(cfg, neverProbe)
	if err := svc.RebuildFromDisk(); err != nil {
		t.Fatalf("RebuildFromDisk: %v", err)
	}
	if !svc.IsParked("codex-foo.json") || !svc.IsParked("codex-bar.json") {
		t.Fatalf("rebuild missed entries: %+v", svc.Snapshot())
	}
	for _, info := range svc.Snapshot() {
		if !info.LastProbeAt.IsZero() {
			t.Errorf("LastProbeAt should be zero after rebuild, got %v", info.LastProbeAt)
		}
		if info.ParkedAt.IsZero() {
			t.Errorf("ParkedAt should be set from mtime, got zero")
		}
	}
}

func TestServiceNoticeRestoredClearsStateAndStartsGrace(t *testing.T) {
	dir := t.TempDir()
	authID := "codex-foo.json"
	writeFile(t, filepath.Join(dir, authID), `{"type":"codex"}`)

	cfg := newTestCfg(t, dir)
	svc := New(cfg, neverProbe)

	now := time.Now()
	svc.observe429(authID, "codex", "gpt-5.4", now)
	svc.observe429(authID, "codex", "gpt-5.4", now.Add(time.Second))
	if !svc.IsParked(authID) {
		t.Fatal("setup failed: auth not parked")
	}
	svc.NoticeRestored(authID)
	if svc.IsParked(authID) {
		t.Fatal("NoticeRestored must drop the entry")
	}
	// New 429 inside grace window must not re-park.
	if svc.observe429(authID, "codex", "gpt-5.4", now.Add(2*time.Second)) {
		t.Fatal("429 inside grace window must not trigger park")
	}
}

func TestServiceProberCallsProbeAndUnparks(t *testing.T) {
	dir := t.TempDir()
	authID := "codex-foo.json"
	writeFile(t, filepath.Join(dir, ".disabled", authID), `{"type":"codex"}`)

	cfg := newTestCfg(t, dir)
	// Force a tiny interval so the prober ticks fast.
	cfg.QuotaPark.Probe.Interval = "10ms"

	var calls atomic.Int32
	probe := func(ctx context.Context, info ParkedInfo) (ProbeResult, error) {
		calls.Add(1)
		return ProbeRecovered, nil
	}
	svc := New(cfg, probe)
	if err := svc.RebuildFromDisk(); err != nil {
		t.Fatalf("RebuildFromDisk: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)
	defer svc.Stop()

	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("probe never produced unpark, calls=%d still parked=%v", calls.Load(), svc.IsParked(authID))
		default:
		}
		if !svc.IsParked(authID) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, statErr := os.Stat(filepath.Join(dir, authID)); statErr != nil {
		t.Fatalf("unparked file should exist in active dir: %v", statErr)
	}
}

func neverProbe(ctx context.Context, info ParkedInfo) (ProbeResult, error) {
	return ProbeStillExhausted, nil
}
