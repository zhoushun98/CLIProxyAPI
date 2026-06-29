package auth

// codex_guard.go implements automatic disable-on-429 and delete-on-401 behavior
// for Codex credentials. The guard is composed of pure helpers (metadata I/O,
// status decisions) plus a small number of Manager methods that need access to
// the executor registry and store for refresh probes and three-step deletion.
//
// All guard behavior is opt-in via Config.Codex.AuthGuard. With the default
// config the helpers compile in but never observe state, so legacy cooldown
// behavior is preserved.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	log "github.com/sirupsen/logrus"
)

const (
	codexProviderName = "codex"

	// Metadata keys persisted into Auth.Metadata. They survive store.Save() /
	// store.List() round-trips and are visible to the management UI which
	// already renders arbitrary metadata.
	codexMetaDisabledReason = "codex_disabled_reason"
	codexMetaDisabledUntil  = "codex_disabled_until"
	codexMetaDisabledAt     = "codex_disabled_at"
	codexMeta401Streak      = "codex_401_streak"
	codexMeta401LastAt      = "codex_401_last_at"

	codexDisabledReasonQuota = "quota_exhausted"

	codexQuotaRecoveryResetsAt = "resets-at"
	codexQuotaRecoveryManual   = "manual"

	codexDefaultSweepInterval   = 30 * time.Second
	codexDefaultStreakWindow    = 10 * time.Minute
	codexDefaultStreakThreshold = 3
)

// effectiveCodexGuardConfig is the parsed/defaulted view of CodexAuthGuardConfig.
// Time fields are resolved once here so the hot path does not re-parse strings.
type effectiveCodexGuardConfig struct {
	DisableOnQuotaExhausted     bool
	QuotaRecoveryMode           string
	RecoverySweepInterval       time.Duration
	RefreshBeforeUnauthorized   bool
	DeleteOnUnauthorized        bool
	UnauthorizedStreakThreshold int
	UnauthorizedStreakWindow    time.Duration
}

// codexGuardConfig returns the effective guard config from the manager's
// atomic runtime config snapshot. Always returns a usable value — missing or
// malformed entries fall back to documented defaults.
func (m *Manager) codexGuardConfig() effectiveCodexGuardConfig {
	if m == nil {
		return defaultCodexGuardConfig()
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil {
		return defaultCodexGuardConfig()
	}
	return resolveCodexGuardConfig(cfg.Codex.AuthGuard)
}

func defaultCodexGuardConfig() effectiveCodexGuardConfig {
	return effectiveCodexGuardConfig{
		QuotaRecoveryMode:           codexQuotaRecoveryResetsAt,
		RecoverySweepInterval:       codexDefaultSweepInterval,
		UnauthorizedStreakThreshold: codexDefaultStreakThreshold,
		UnauthorizedStreakWindow:    codexDefaultStreakWindow,
	}
}

func resolveCodexGuardConfig(raw internalconfig.CodexAuthGuardConfig) effectiveCodexGuardConfig {
	out := effectiveCodexGuardConfig{
		DisableOnQuotaExhausted:     raw.DisableOnQuotaExhausted,
		QuotaRecoveryMode:           strings.TrimSpace(raw.QuotaRecoveryMode),
		RefreshBeforeUnauthorized:   raw.RefreshBeforeUnauthorized,
		DeleteOnUnauthorized:        raw.DeleteOnUnauthorized,
		UnauthorizedStreakThreshold: raw.UnauthorizedStreakThreshold,
	}
	if out.QuotaRecoveryMode != codexQuotaRecoveryManual {
		// Default + any unknown value normalizes to "resets-at".
		out.QuotaRecoveryMode = codexQuotaRecoveryResetsAt
	}
	if d, err := time.ParseDuration(strings.TrimSpace(raw.RecoverySweepInterval)); err == nil && d > 0 {
		out.RecoverySweepInterval = d
	} else {
		out.RecoverySweepInterval = codexDefaultSweepInterval
	}
	if d, err := time.ParseDuration(strings.TrimSpace(raw.UnauthorizedStreakWindow)); err == nil && d > 0 {
		out.UnauthorizedStreakWindow = d
	} else {
		out.UnauthorizedStreakWindow = codexDefaultStreakWindow
	}
	if out.UnauthorizedStreakThreshold <= 0 {
		out.UnauthorizedStreakThreshold = codexDefaultStreakThreshold
	}
	return out
}

// === Metadata helpers ===
//
// Metadata is a free-form map[string]any. We always serialize our values as
// strings to keep JSON encoding deterministic across persistence backends, and
// because integers in YAML/JSON can round-trip as float64 which we'd then have
// to reconvert.

func codexMetaString(auth *Auth, key string) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	v, ok := auth.Metadata[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func codexMetaInt(auth *Auth, key string) int {
	s := codexMetaString(auth, key)
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func codexMetaTime(auth *Auth, key string) time.Time {
	s := codexMetaString(auth, key)
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func codexSetMeta(auth *Auth, key, value string) {
	if auth == nil {
		return
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata[key] = value
}

func codexClearMeta(auth *Auth, keys ...string) {
	if auth == nil || auth.Metadata == nil {
		return
	}
	for _, k := range keys {
		delete(auth.Metadata, k)
	}
}

// === Provider / result classification ===

func isCodexAuth(auth *Auth) bool {
	if auth == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(auth.Provider), codexProviderName)
}

func isCodexResult(result Result) bool {
	return strings.EqualFold(strings.TrimSpace(result.Provider), codexProviderName)
}

// === 429: persistent disable ===

// markCodexQuotaDisabled flips Auth.Disabled and records the quota disable
// metadata. Returns true when state actually changed (so callers can avoid
// noisy logs / persistence churn on repeated 429s for an already-disabled auth).
//
// Must run with m.mu held — modifies Auth in place. Persistence happens via
// the caller's m.persist() call later in the MarkResult flow.
func markCodexQuotaDisabled(auth *Auth, cfg effectiveCodexGuardConfig, retryAfter *time.Duration, now time.Time) bool {
	if auth == nil {
		return false
	}
	var until time.Time
	if cfg.QuotaRecoveryMode == codexQuotaRecoveryResetsAt && retryAfter != nil && *retryAfter > 0 {
		// Truncate to second granularity so the value we persist round-trips
		// equal to itself after RFC3339 parse (RFC3339 has 1s precision).
		until = now.Add(*retryAfter).Truncate(time.Second)
	}

	alreadyQuotaDisabled := auth.Disabled &&
		codexMetaString(auth, codexMetaDisabledReason) == codexDisabledReasonQuota
	if alreadyQuotaDisabled {
		// Update the until window in case OpenAI bumped the reset time on a
		// subsequent 429, but skip the rest of the bookkeeping if it's identical.
		if codexMetaTime(auth, codexMetaDisabledUntil).Equal(until) {
			return false
		}
	}

	auth.Disabled = true
	auth.Status = StatusDisabled
	auth.StatusMessage = "codex auth-guard: quota exhausted"
	codexSetMeta(auth, codexMetaDisabledReason, codexDisabledReasonQuota)
	codexSetMeta(auth, codexMetaDisabledAt, now.UTC().Format(time.RFC3339))
	if !until.IsZero() {
		codexSetMeta(auth, codexMetaDisabledUntil, until.UTC().Format(time.RFC3339))
	} else {
		// Manual mode (or missing retryAfter): drop any stale window so the
		// sweeper sees "no scheduled recovery" instead of an old timestamp.
		codexClearMeta(auth, codexMetaDisabledUntil)
	}
	auth.UpdatedAt = now
	return true
}

// clearCodexQuotaDisabled removes the quota-disable state, restoring Disabled=false
// and clearing the related metadata. Returns true when state actually changed.
//
// Only clears state owned by the quota disable path — credentials disabled for
// other reasons (operator action, future guards) are left alone.
//
// Must run with m.mu held.
func clearCodexQuotaDisabled(auth *Auth, now time.Time) bool {
	if auth == nil || !auth.Disabled {
		return false
	}
	if codexMetaString(auth, codexMetaDisabledReason) != codexDisabledReasonQuota {
		return false
	}
	auth.Disabled = false
	if auth.Status == StatusDisabled {
		auth.Status = StatusActive
	}
	if strings.HasPrefix(auth.StatusMessage, "codex auth-guard:") {
		auth.StatusMessage = ""
	}
	codexClearMeta(auth, codexMetaDisabledReason, codexMetaDisabledUntil, codexMetaDisabledAt)
	auth.UpdatedAt = now
	return true
}

// codexQuotaDisabledExpired reports whether a quota-disabled auth has reached
// its recovery window. Returns false for manual-mode credentials (until == zero).
func codexQuotaDisabledExpired(auth *Auth, now time.Time) bool {
	if auth == nil || !auth.Disabled {
		return false
	}
	if codexMetaString(auth, codexMetaDisabledReason) != codexDisabledReasonQuota {
		return false
	}
	until := codexMetaTime(auth, codexMetaDisabledUntil)
	if until.IsZero() {
		return false // manual mode — operator action required
	}
	return !until.After(now)
}

// === 401: streak counter ===

// bumpCodexUnauthorizedStreak increments the 401 streak, resetting it first if
// the previous failure falls outside the rolling window. Returns the new count.
//
// Must run with m.mu held.
func bumpCodexUnauthorizedStreak(auth *Auth, now time.Time, window time.Duration) int {
	if auth == nil {
		return 0
	}
	streak := codexMetaInt(auth, codexMeta401Streak)
	last := codexMetaTime(auth, codexMeta401LastAt)
	if window > 0 && !last.IsZero() && now.Sub(last) > window {
		streak = 0
	}
	streak++
	codexSetMeta(auth, codexMeta401Streak, strconv.Itoa(streak))
	codexSetMeta(auth, codexMeta401LastAt, now.UTC().Format(time.RFC3339))
	return streak
}

// clearCodexUnauthorizedStreak removes the streak metadata. Returns true when
// the auth state actually changed. Must run with m.mu held.
func clearCodexUnauthorizedStreak(auth *Auth) bool {
	if auth == nil || auth.Metadata == nil {
		return false
	}
	_, hadStreak := auth.Metadata[codexMeta401Streak]
	_, hadLast := auth.Metadata[codexMeta401LastAt]
	if !hadStreak && !hadLast {
		return false
	}
	codexClearMeta(auth, codexMeta401Streak, codexMeta401LastAt)
	return true
}

// === Refresh probe ===

// codexRefreshProbeOutcome captures what runCodexRefreshProbe observed about a
// 401-triggered refresh attempt. MarkResult uses it to classify the 401:
// transient access-token expiry (do not bump streak) vs. credential revoked
// (bump streak, possibly trigger delete).
type codexRefreshProbeOutcome struct {
	// Attempted is true when a refresh was actually dispatched (i.e. cfg enabled
	// it, the auth exists, and the codex executor is registered).
	Attempted bool
	// Succeeded is true when refresh returned new tokens and they were persisted.
	Succeeded bool
	// StructuralErr is true when refresh failed with an OAuth-recognized
	// non-retryable code (invalid_grant / refresh_token_reused / etc.) — the
	// strong signal that the credential is actually revoked.
	StructuralErr bool
	// Err carries the raw refresh error for logging.
	Err error
}

// codexRefreshProbeTimeout caps how long a 401-triggered refresh probe may
// block the request goroutine that is processing the failed request. Without
// this ceiling, a stalled auth.openai.com endpoint would hang every 401-handling
// request indefinitely (the underlying refresh uses context.WithoutCancel).
const codexRefreshProbeTimeout = 5 * time.Second

// runCodexRefreshProbe attempts a refresh-token exchange for the given auth
// outside any manager lock. Runs through Manager-scoped singleflight so
// concurrent 401s on the same credential share one network call, and runs
// under a strict timeout so a stalled OAuth endpoint cannot deadline-bomb
// the request thread.
//
// Successful refresh persists new tokens via Manager.Update() so subsequent
// requests immediately benefit. Failure classification is left to the caller.
//
// A "successful" probe requires the executor to return updated material whose
// token actually changed — a credential without a refresh_token causes the
// codex executor to return (auth, nil) as a no-op, which we MUST NOT treat as
// a successful refresh (it would falsely clear the cooldown).
func (m *Manager) runCodexRefreshProbe(ctx context.Context, authID string) codexRefreshProbeOutcome {
	if m == nil || authID == "" {
		return codexRefreshProbeOutcome{}
	}
	cfg := m.codexGuardConfig()
	if !cfg.RefreshBeforeUnauthorized {
		return codexRefreshProbeOutcome{}
	}

	// Snapshot under read lock — we don't hold it across the network call.
	m.mu.RLock()
	auth := m.auths[authID]
	if auth == nil || !isCodexAuth(auth) {
		m.mu.RUnlock()
		return codexRefreshProbeOutcome{}
	}
	cloned := auth.Clone()
	exec, ok := m.executors[strings.ToLower(strings.TrimSpace(cloned.Provider))]
	m.mu.RUnlock()
	if !ok || exec == nil {
		return codexRefreshProbeOutcome{}
	}

	oldAccessToken := codexAccessTokenOf(cloned)

	// Enforce a hard timeout so a stalled refresh endpoint cannot block the
	// request goroutine. Detach from the request context so a fast client
	// disconnect doesn't cancel a refresh that might still help future requests.
	probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), codexRefreshProbeTimeout)
	defer cancel()

	type probeResult struct {
		updated *Auth
		err     error
	}
	v, _, _ := m.codexRefreshGroup.Do(authID, func() (interface{}, error) {
		updated, err := exec.Refresh(probeCtx, cloned)
		return probeResult{updated: updated, err: err}, nil
	})
	res, _ := v.(probeResult)

	out := codexRefreshProbeOutcome{Attempted: true, Err: res.err}
	if res.err == nil && res.updated != nil {
		// Guard against the codex executor's no-op early-return on credentials
		// without a refresh_token: in that case Refresh returns (auth, nil) but
		// the access token is unchanged — counting it as a successful refresh
		// would wrongly clear the 401 cooldown.
		newAccessToken := codexAccessTokenOf(res.updated)
		if newAccessToken != "" && newAccessToken != oldAccessToken {
			out.Succeeded = true
			// Persist new tokens. Failure here is a separate concern from
			// classification: even if persistence fails, the credential is still
			// healthy (the next refresh will retry); we log and move on.
			if _, errUpdate := m.Update(ctx, res.updated); errUpdate != nil {
				log.WithField("auth_id", authID).
					Warnf("codex auth-guard: failed to persist refreshed tokens: %v", errUpdate)
			}
			return out
		}
	}
	if res.err != nil && codexauth.IsNonRetryableRefreshErr(res.err) {
		out.StructuralErr = true
	}
	return out
}

// codexAccessTokenOf extracts the access_token metadata value from a Codex
// auth, treating absent / non-string entries as empty. Used to detect whether
// a Refresh() call actually changed the credential material.
func codexAccessTokenOf(auth *Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	v, ok := auth.Metadata["access_token"]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// === Delete (three-step) ===

// === MarkResult integration ===

// applyCodexGuardPost is invoked by MarkResult after the legacy auth state
// bookkeeping completes (and the manager lock is released). It implements four
// orthogonal behaviors:
//
//   - Success: clear any lingering 401 streak.
//   - 401 + refresh probe succeeded: clear the 30-minute cooldown the legacy
//     401 branch just wrote, so the freshly-refreshed credential is eligible
//     for the next request. Streak is cleared too. The result itself is NOT
//     mutated — Failed++, OnResult, publishErrorEvent all see the real 401.
//   - 429 + DisableOnQuotaExhausted: persistently disable the credential and
//     schedule it for the recovery sweeper.
//   - 401 + DeleteOnUnauthorized: bump the streak and, when the threshold is
//     reached, delete the credential file three-step.
func (m *Manager) applyCodexGuardPost(ctx context.Context, result Result, refresh codexRefreshProbeOutcome, statusCode int) {
	if m == nil || !isCodexResult(result) {
		return
	}
	cfg := m.codexGuardConfig()

	if result.Success {
		m.clearCodexStreakAndPersist(ctx, result.AuthID)
		return
	}

	switch statusCode {
	case 429:
		if !cfg.DisableOnQuotaExhausted {
			return
		}
		m.applyCodexQuotaDisablePost(ctx, result, cfg)
	case 401:
		if refresh.Succeeded {
			// Refresh probe succeeded: the 30-minute unauthorized cooldown
			// the legacy 401 branch just installed is now wrong — the
			// credential has fresh tokens and is eligible immediately.
			m.clearCodexUnauthorizedCooldown(ctx, result)
			return
		}
		if !cfg.DeleteOnUnauthorized {
			return
		}
		// Only "real" 401s feed the streak: those we never probed (probe
		// disabled), and those where probe failed with a structural OAuth code
		// (invalid_grant et al.). Probe attempts that failed transiently —
		// network blip, 5xx from the OAuth server — get a free pass so we don't
		// nuke a credential because of an unrelated outage.
		if refresh.Attempted && !refresh.StructuralErr {
			return
		}
		m.applyCodexUnauthorizedPost(ctx, result, cfg)
	}
}

// clearCodexUnauthorizedCooldown reverses the 30-minute cooldown the standard
// 401 path just wrote when a refresh probe demonstrates the credential is
// actually healthy. Touches the affected model state (when result.Model is
// set) and the auth-level fields, leaves Success/Failed counters and the
// emitted error event untouched. Must run outside m.mu (callers persist the
// snapshot after releasing).
func (m *Manager) clearCodexUnauthorizedCooldown(ctx context.Context, result Result) {
	authID := result.AuthID
	if authID == "" {
		return
	}
	m.mu.Lock()
	auth, ok := m.auths[authID]
	if !ok || auth == nil || !isCodexAuth(auth) {
		m.mu.Unlock()
		return
	}
	now := time.Now()
	if result.Model != "" {
		if state, ok := auth.ModelStates[result.Model]; ok && state != nil {
			state.Unavailable = false
			state.Status = StatusActive
			state.StatusMessage = ""
			state.NextRetryAfter = time.Time{}
			state.LastError = nil
			state.UpdatedAt = now
		}
	}
	auth.Unavailable = false
	if auth.Status == StatusError {
		auth.Status = StatusActive
	}
	auth.StatusMessage = ""
	auth.NextRetryAfter = time.Time{}
	auth.LastError = nil
	auth.UpdatedAt = now
	clearCodexUnauthorizedStreak(auth)
	updateAggregatedAvailability(auth, now)
	snapshot := auth.Clone()
	m.mu.Unlock()

	if err := m.persist(ctx, snapshot); err != nil {
		log.WithField("auth_id", snapshot.ID).
			Warnf("codex auth-guard: failed to persist refresh-recovered auth: %v", err)
	}
	if m.scheduler != nil {
		m.scheduler.upsertAuth(snapshot)
	}
	// Resume registry-suspended model so the route is selectable on the next
	// request, mirroring ResetQuota's notify pattern.
	if result.Model != "" {
		registry.GetGlobalRegistry().ResumeClientModel(snapshot.ID, result.Model)
	}
	log.WithFields(log.Fields{
		"auth_id":  snapshot.ID,
		"provider": codexProviderName,
		"action":   "refresh_cleared_cooldown",
		"reason":   "refresh_probe_succeeded",
	}).Info("codex auth-guard: cleared unauthorized cooldown after successful refresh probe")
}

// clearCodexStreakAndPersist clears the 401 streak metadata after a successful
// codex request. Uses an RLock fast-path because the steady-state case is
// "no streak to clear" — taking the write lock on every successful request
// would contend with refresh / update / scheduler operations on busy
// deployments.
func (m *Manager) clearCodexStreakAndPersist(ctx context.Context, authID string) {
	if authID == "" {
		return
	}
	// Fast path under RLock: only escalate to the write lock when the streak
	// metadata is actually present.
	m.mu.RLock()
	auth, ok := m.auths[authID]
	if !ok || auth == nil || !isCodexAuth(auth) || !codexAuthHasStreakMetadata(auth) {
		m.mu.RUnlock()
		return
	}
	m.mu.RUnlock()

	m.mu.Lock()
	auth, ok = m.auths[authID]
	if !ok || auth == nil || !isCodexAuth(auth) {
		m.mu.Unlock()
		return
	}
	changed := clearCodexUnauthorizedStreak(auth)
	var snapshot *Auth
	if changed {
		snapshot = auth.Clone()
	}
	m.mu.Unlock()

	if !changed || snapshot == nil {
		return
	}
	if err := m.persist(ctx, snapshot); err != nil {
		log.WithField("auth_id", snapshot.ID).
			Warnf("codex auth-guard: failed to persist cleared 401 streak: %v", err)
	}
}

// codexAuthHasStreakMetadata cheaply reports whether either streak key exists
// on the auth's Metadata map. Safe to call under RLock.
func codexAuthHasStreakMetadata(auth *Auth) bool {
	if auth == nil || auth.Metadata == nil {
		return false
	}
	_, hasStreak := auth.Metadata[codexMeta401Streak]
	if hasStreak {
		return true
	}
	_, hasLast := auth.Metadata[codexMeta401LastAt]
	return hasLast
}

func (m *Manager) applyCodexQuotaDisablePost(ctx context.Context, result Result, cfg effectiveCodexGuardConfig) {
	m.mu.Lock()
	auth, ok := m.auths[result.AuthID]
	if !ok || auth == nil || !isCodexAuth(auth) {
		m.mu.Unlock()
		return
	}
	now := time.Now()
	changed := markCodexQuotaDisabled(auth, cfg, result.RetryAfter, now)
	var snapshot *Auth
	if changed {
		snapshot = auth.Clone()
	}
	m.mu.Unlock()

	if !changed || snapshot == nil {
		return
	}
	if err := m.persist(ctx, snapshot); err != nil {
		log.WithField("auth_id", snapshot.ID).
			Warnf("codex auth-guard: failed to persist quota disable: %v", err)
	}
	if m.scheduler != nil {
		m.scheduler.upsertAuth(snapshot)
	}
	fields := log.Fields{
		"auth_id":  snapshot.ID,
		"provider": codexProviderName,
		"action":   "auto_disable",
		"reason":   "http_429",
	}
	if until := codexMetaString(snapshot, codexMetaDisabledUntil); until != "" {
		fields["disabled_until"] = until
	} else {
		fields["recovery_mode"] = codexQuotaRecoveryManual
	}
	log.WithFields(fields).Warn("codex auth-guard: disabled credential after quota exhausted")
}

func (m *Manager) applyCodexUnauthorizedPost(ctx context.Context, result Result, cfg effectiveCodexGuardConfig) {
	m.mu.Lock()
	auth, ok := m.auths[result.AuthID]
	if !ok || auth == nil || !isCodexAuth(auth) {
		m.mu.Unlock()
		return
	}
	now := time.Now()
	streak := bumpCodexUnauthorizedStreak(auth, now, cfg.UnauthorizedStreakWindow)
	snapshot := auth.Clone()
	shouldDelete := streak >= cfg.UnauthorizedStreakThreshold
	m.mu.Unlock()

	if !shouldDelete {
		if err := m.persist(ctx, snapshot); err != nil {
			log.WithField("auth_id", snapshot.ID).
				Warnf("codex auth-guard: failed to persist 401 streak: %v", err)
		}
		log.WithFields(log.Fields{
			"auth_id":   snapshot.ID,
			"provider":  codexProviderName,
			"action":    "streak_bump",
			"streak":    streak,
			"threshold": cfg.UnauthorizedStreakThreshold,
		}).Warn("codex auth-guard: unauthorized streak incremented")
		return
	}

	// Streak threshold reached — delete the credential file across all layers.
	path := authAttribute(snapshot, AttributePath)
	if err := m.deleteCodexAuthFile(ctx, snapshot); err != nil {
		log.WithFields(log.Fields{
			"auth_id":  snapshot.ID,
			"provider": codexProviderName,
			"file":     path,
		}).Errorf("codex auth-guard: failed to delete credential after %d unauthorized failures: %v", streak, err)
		return
	}
	log.WithFields(log.Fields{
		"auth_id":  snapshot.ID,
		"provider": codexProviderName,
		"action":   "auto_delete",
		"reason":   "http_401_persistent",
		"streak":   streak,
		"file":     path,
	}).Warnf("codex auth-guard: deleted credential after %d consecutive unauthorized failures", streak)
}

// deleteCodexAuthFile removes a codex credential across all storage layers:
// disk file → configured store backend → in-memory manager entry. Idempotent
// across each step. Runs outside m.mu.
//
// The order is intentional:
//
//  1. os.Remove first so that even if step 2 or 3 fails, the secret material
//     is no longer readable from disk.
//  2. store.Delete second to clear postgres/git/object backends so List()
//     cannot resurrect the entry on restart. FileTokenStore.Delete is a
//     no-op when the file is missing, which is fine.
//  3. Manager.Remove last to evict from in-memory state.
//
// The fsnotify Remove event triggered by step 1 will eventually invoke
// Manager.Remove a second time; that path is already idempotent.
func (m *Manager) deleteCodexAuthFile(ctx context.Context, auth *Auth) error {
	if m == nil || auth == nil {
		return errors.New("codex auth-guard: nil manager or auth")
	}
	authID := strings.TrimSpace(auth.ID)
	if authID == "" {
		return errors.New("codex auth-guard: missing auth id")
	}
	path := strings.TrimSpace(authAttribute(auth, AttributePath))

	var diskErr, storeErr error
	if path != "" {
		if errRemove := os.Remove(path); errRemove != nil && !errors.Is(errRemove, os.ErrNotExist) {
			diskErr = fmt.Errorf("remove file %s: %w", path, errRemove)
		}
	}
	if m.store != nil {
		if errStore := m.store.Delete(ctx, authID); errStore != nil {
			storeErr = fmt.Errorf("store delete %s: %w", authID, errStore)
		}
	}
	m.Remove(ctx, authID)

	// errors.Join preserves the %w chain for each inner cause (so errors.Is /
	// errors.As against the joined result still finds disk or store sentinels)
	// and returns nil when all inputs are nil.
	return errors.Join(diskErr, storeErr)
}
