package quotapark

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// Service is the top-level entry point for the quota-park feature. It wires
// the tracker, mover, state store, and prober together, exposes a Hook for
// the conductor, and manages startup/shutdown.
type Service struct {
	mu      sync.Mutex
	cfg     *config.Config
	tracker *tracker
	state   *stateStore
	mover   *mover
	prober  *prober

	// providerFilter restricts which provider strings are considered for parking.
	// Empty set means "no restriction".
	providerFilter map[string]struct{}

	// Disabled when true the service performs no work even though it is wired.
	disabled bool

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// ParkScope returns the set of provider strings the service will park.
type ParkScope struct {
	Providers []string
}

// New constructs a Service from the given config and probe function. The probe
// function is typically a method value on CodexProber but is injected so that
// tests can substitute a stub.
func New(cfg *config.Config, probe ProbeFunc) *Service {
	qp := cfg.QuotaPark
	window, _ := time.ParseDuration(qp.Trigger.Window)
	if window <= 0 {
		window = 3 * time.Minute
	}
	grace, _ := time.ParseDuration(qp.Trigger.GraceAfterUnpark)
	if grace < 0 {
		grace = 60 * time.Second
	}
	interval, _ := time.ParseDuration(qp.Probe.Interval)
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	state := newStateStore()
	trk := newTracker(window, grace, qp.Trigger.Count)
	mv := newMover(strings.TrimSpace(cfg.AuthDir), strings.TrimSpace(qp.Directory))
	pr := newProber(state, trk, mv, probe, interval)

	return &Service{
		cfg:            cfg,
		tracker:        trk,
		state:          state,
		mover:          mv,
		prober:         pr,
		providerFilter: defaultProviderFilter(),
		disabled:       !qp.Enabled,
	}
}

// defaultProviderFilter returns the v1 scope: only codex.
func defaultProviderFilter() map[string]struct{} {
	return map[string]struct{}{"codex": {}}
}

// Hook returns the coreauth.Hook implementation that bridges this Service
// to the conductor. Safe to call multiple times; the returned value is a
// fresh adapter each call.
func (s *Service) Hook() coreauth.Hook { return &Hook{svc: s} }

// AuthDir returns the resolved active auth directory.
func (s *Service) AuthDir() string { return s.mover.AuthDir() }

// ParkedDir returns the resolved parking directory.
func (s *Service) ParkedDir() string { return s.mover.ParkedDir() }

// IsParked reports whether the given authID is currently parked.
func (s *Service) IsParked(authID string) bool { return s.state.Has(authID) }

// Snapshot returns the current parked entries (for debug / management views).
func (s *Service) Snapshot() []ParkedInfo { return s.state.Snapshot() }

// NoticeRestored is called from the watcher wiring when an authID that we
// were tracking as parked reappears in the active directory (typically because
// the operator restored it manually). We drop the entry and start a grace
// window so the next 429 burst does not immediately re-park it.
func (s *Service) NoticeRestored(authID string) {
	if s.disabled || authID == "" {
		return
	}
	if !s.state.Has(authID) {
		return
	}
	s.state.Delete(authID)
	s.tracker.StartGrace(authID, time.Now())
	log.WithFields(log.Fields{"auth_id": authID}).Info("quota-park: noticed manual restore |")
}

// RebuildFromDisk scans <parkedDir>/*.json and populates the in-memory state
// so that probes resume after a process restart.
func (s *Service) RebuildFromDisk() error {
	if s.disabled {
		return nil
	}
	dir := s.mover.ParkedDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("quota-park: read parked dir: %w", err)
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		full := filepath.Join(dir, e.Name())
		fi, errStat := e.Info()
		var parkedAt time.Time
		if errStat == nil {
			parkedAt = fi.ModTime()
		}
		info := ParkedInfo{
			AuthID:          e.Name(),
			OriginalAbsPath: filepath.Join(s.mover.AuthDir(), e.Name()),
			ParkedAbsPath:   full,
			Provider:        "codex", // v1 only parks codex; non-codex entries skipped at park time
			ParkedAt:        parkedAt,
		}
		s.state.Put(info)
		count++
	}
	if count > 0 {
		log.WithFields(log.Fields{"parked": count}).Info("quota-park: rebuilt state from disk |")
	}
	return nil
}

// Start launches the prober goroutine. ctx cancellation stops the prober.
// Calling Start more than once is a no-op after the first call.
func (s *Service) Start(ctx context.Context) {
	if s.disabled {
		return
	}
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return
	}
	pctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.mu.Unlock()

	log.WithFields(log.Fields{
		"window":            s.cfg.QuotaPark.Trigger.Window,
		"count":             s.cfg.QuotaPark.Trigger.Count,
		"interval":          s.cfg.QuotaPark.Probe.Interval,
		"grace-after-unpark": s.cfg.QuotaPark.Trigger.GraceAfterUnpark,
		"dir":               s.cfg.QuotaPark.Directory,
		"model":             s.cfg.QuotaPark.Probe.Model,
	}).Info("quota-park: enabled |")

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.prober.run(pctx)
	}()
}

// Stop cancels the prober goroutine and waits for it to exit.
func (s *Service) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
}

// observe429 is invoked by the Hook when the conductor reports a 429.
// Returns true if this call triggered a park.
func (s *Service) observe429(authID, provider, model string, at time.Time) bool {
	if s.disabled || authID == "" {
		return false
	}
	if len(s.providerFilter) > 0 {
		if _, ok := s.providerFilter[strings.ToLower(strings.TrimSpace(provider))]; !ok {
			return false
		}
	}
	if s.state.Has(authID) {
		log.WithFields(log.Fields{"auth_id": authID}).Debug("quota-park: park no-op already parked |")
		return false
	}
	if !s.tracker.Observe429(authID, at) {
		log.WithFields(log.Fields{
			"auth_id": authID,
			"count":   s.tracker.hitCount(authID),
			"window":  s.cfg.QuotaPark.Trigger.Window,
		}).Debug("quota-park: tracker hit |")
		return false
	}
	return s.performPark(authID, provider, model, at)
}

// performPark moves the file and records state. Idempotent: a second call for
// an authID that is already parked returns false without side effects.
func (s *Service) performPark(authID, provider, model string, at time.Time) bool {
	if s.state.Has(authID) {
		log.WithFields(log.Fields{"auth_id": authID}).Debug("quota-park: park no-op already parked |")
		return false
	}
	parkedPath, err := s.mover.Park(authID)
	if err != nil {
		log.WithFields(log.Fields{"auth_id": authID, "err": err.Error()}).Warn("quota-park: park rename failed |")
		return false
	}
	info := ParkedInfo{
		AuthID:          authID,
		OriginalAbsPath: filepath.Join(s.mover.AuthDir(), authID),
		ParkedAbsPath:   parkedPath,
		Provider:        provider,
		ParkedAt:        at,
	}
	s.state.Put(info)
	// Reset the 429 ring buffer so a future unpark starts from scratch.
	s.tracker.Reset(authID)
	log.WithFields(log.Fields{
		"auth_id": authID,
		"model":   model,
		"path":    parkedPath,
	}).Info("quota-park: parking |")
	return true
}

// markSuccess clears the 429 ring buffer when an auth completes a successful
// request, so accumulated hits do not trigger a future park unfairly.
func (s *Service) markSuccess(authID string) {
	if s.disabled || authID == "" {
		return
	}
	s.tracker.Reset(authID)
}
