package auth

// cooldown_recovery_loop.go drives the background sweeper that re-enables Codex
// credentials whose 429 disable window has elapsed. It runs as an independent
// goroutine in parallel with StartAutoRefresh: the two loops touch disjoint
// state (auto-refresh manages token freshness, the recovery sweeper manages
// quota-disable status), so keeping them separate avoids subtle interactions.

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
)

// StartCooldownRecoveryLoop starts (or restarts) the background sweeper that
// re-enables Codex credentials disabled by codex_guard's 429 path once their
// recorded recovery window has elapsed. Stopping the loop is done by
// StopCooldownRecoveryLoop or by cancelling parent.
//
// Calling Start a second time cancels the prior loop, mirroring StartAutoRefresh.
// A zero or negative interval falls back to codexDefaultSweepInterval.
func (m *Manager) StartCooldownRecoveryLoop(parent context.Context, interval time.Duration) {
	if m == nil {
		return
	}
	if interval <= 0 {
		interval = codexDefaultSweepInterval
	}

	m.mu.Lock()
	cancelPrev := m.cooldownRecoveryCancel
	m.cooldownRecoveryCancel = nil
	m.mu.Unlock()
	if cancelPrev != nil {
		cancelPrev()
	}

	if parent == nil {
		parent = context.Background()
	}
	ctx, cancelCtx := context.WithCancel(parent)

	m.mu.Lock()
	m.cooldownRecoveryCancel = cancelCtx
	m.mu.Unlock()

	log.Infof("codex auth-guard: cooldown recovery sweeper started (interval=%s)", interval)
	go m.runCooldownRecoveryLoop(ctx, interval)
}

// StopCooldownRecoveryLoop cancels the recovery sweeper if running. Safe to
// call when no loop is active.
func (m *Manager) StopCooldownRecoveryLoop() {
	if m == nil {
		return
	}
	m.mu.Lock()
	cancel := m.cooldownRecoveryCancel
	m.cooldownRecoveryCancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (m *Manager) runCooldownRecoveryLoop(ctx context.Context, initialInterval time.Duration) {
	interval := initialInterval
	timer := time.NewTimer(interval)
	defer timer.Stop()

	// Run an immediate sweep so restarts pick up credentials whose recovery
	// time already passed while the server was down.
	m.sweepCodexQuotaDisabled(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Debug("codex auth-guard: cooldown recovery sweeper stopped")
			return
		case <-timer.C:
			m.sweepCodexQuotaDisabled(ctx)
			// Re-read the configured interval each tick so YAML hot-reloads
			// (config.codex.auth-guard.recovery-sweep-interval) take effect
			// without requiring a process restart — matching the hot-reload
			// behavior of the other auth-guard knobs.
			next := m.codexGuardConfig().RecoverySweepInterval
			if next <= 0 {
				next = initialInterval
			}
			if next != interval {
				log.WithFields(log.Fields{
					"old": interval,
					"new": next,
				}).Info("codex auth-guard: recovery sweep interval changed")
				interval = next
			}
			timer.Reset(interval)
		}
	}
}

// sweepCodexQuotaDisabled walks all in-memory credentials and re-enables any
// Codex credential whose quota disable window has elapsed. Persistence and
// scheduler refresh happen outside the manager lock to keep tick latency low
// even with many credentials.
func (m *Manager) sweepCodexQuotaDisabled(ctx context.Context) {
	if m == nil {
		return
	}
	now := time.Now()

	// Phase 1: collect-and-mutate under the manager lock. We clone after
	// mutation so the snapshot we persist matches the in-memory state.
	var recovered []*Auth
	m.mu.Lock()
	for _, auth := range m.auths {
		if auth == nil || !isCodexAuth(auth) {
			continue
		}
		if !codexQuotaDisabledExpired(auth, now) {
			continue
		}
		if !clearCodexQuotaDisabled(auth, now) {
			continue
		}
		recovered = append(recovered, auth.Clone())
	}
	m.mu.Unlock()

	if len(recovered) == 0 {
		return
	}

	// Phase 2: persist + scheduler refresh outside the lock. Persistence errors
	// are logged but do not stop the loop — next tick (or next MarkResult) will
	// re-persist the same state.
	for _, snapshot := range recovered {
		if err := m.persist(ctx, snapshot); err != nil {
			log.WithField("auth_id", snapshot.ID).
				Warnf("codex auth-guard: failed to persist auto-recovered auth: %v", err)
		}
		if m.scheduler != nil {
			m.scheduler.upsertAuth(snapshot)
		}
		log.WithFields(log.Fields{
			"auth_id":  snapshot.ID,
			"provider": codexProviderName,
			"action":   "auto_enable",
			"reason":   "quota_window_expired",
		}).Info("codex auth-guard: re-enabled credential after quota window expired")
	}
}
