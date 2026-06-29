package auth

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// === resolveCodexGuardConfig ===

func TestResolveCodexGuardConfig_AppliesDefaults(t *testing.T) {
	got := resolveCodexGuardConfig(internalconfig.CodexAuthGuardConfig{})

	if got.QuotaRecoveryMode != codexQuotaRecoveryResetsAt {
		t.Errorf("QuotaRecoveryMode = %q, want %q", got.QuotaRecoveryMode, codexQuotaRecoveryResetsAt)
	}
	if got.RecoverySweepInterval != codexDefaultSweepInterval {
		t.Errorf("RecoverySweepInterval = %s, want %s", got.RecoverySweepInterval, codexDefaultSweepInterval)
	}
	if got.UnauthorizedStreakThreshold != codexDefaultStreakThreshold {
		t.Errorf("UnauthorizedStreakThreshold = %d, want %d", got.UnauthorizedStreakThreshold, codexDefaultStreakThreshold)
	}
	if got.UnauthorizedStreakWindow != codexDefaultStreakWindow {
		t.Errorf("UnauthorizedStreakWindow = %s, want %s", got.UnauthorizedStreakWindow, codexDefaultStreakWindow)
	}
	if got.DisableOnQuotaExhausted || got.DeleteOnUnauthorized || got.RefreshBeforeUnauthorized {
		t.Errorf("zero-value config must leave bool toggles false, got %+v", got)
	}
}

func TestResolveCodexGuardConfig_NormalizesUnknownRecoveryMode(t *testing.T) {
	got := resolveCodexGuardConfig(internalconfig.CodexAuthGuardConfig{
		QuotaRecoveryMode: "bogus-mode",
	})
	if got.QuotaRecoveryMode != codexQuotaRecoveryResetsAt {
		t.Errorf("unknown mode must normalize to %q, got %q", codexQuotaRecoveryResetsAt, got.QuotaRecoveryMode)
	}
}

func TestResolveCodexGuardConfig_AcceptsManualMode(t *testing.T) {
	got := resolveCodexGuardConfig(internalconfig.CodexAuthGuardConfig{
		QuotaRecoveryMode: "manual",
	})
	if got.QuotaRecoveryMode != codexQuotaRecoveryManual {
		t.Errorf("manual mode lost during normalization, got %q", got.QuotaRecoveryMode)
	}
}

func TestResolveCodexGuardConfig_ParsesDurationsAndIgnoresInvalid(t *testing.T) {
	got := resolveCodexGuardConfig(internalconfig.CodexAuthGuardConfig{
		RecoverySweepInterval:    "1m30s",
		UnauthorizedStreakWindow: "not-a-duration",
	})
	if want := 90 * time.Second; got.RecoverySweepInterval != want {
		t.Errorf("RecoverySweepInterval = %s, want %s", got.RecoverySweepInterval, want)
	}
	if got.UnauthorizedStreakWindow != codexDefaultStreakWindow {
		t.Errorf("invalid duration must fall back to default, got %s", got.UnauthorizedStreakWindow)
	}
}

// === metadata helpers ===

func TestCodexMetaHelpers_RoundTrip(t *testing.T) {
	auth := &Auth{}

	codexSetMeta(auth, codexMetaDisabledReason, codexDisabledReasonQuota)
	codexSetMeta(auth, codexMeta401Streak, "7")
	now := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	codexSetMeta(auth, codexMetaDisabledUntil, now.Format(time.RFC3339))

	if got := codexMetaString(auth, codexMetaDisabledReason); got != codexDisabledReasonQuota {
		t.Errorf("string round-trip = %q, want %q", got, codexDisabledReasonQuota)
	}
	if got := codexMetaInt(auth, codexMeta401Streak); got != 7 {
		t.Errorf("int round-trip = %d, want 7", got)
	}
	if got := codexMetaTime(auth, codexMetaDisabledUntil); !got.Equal(now) {
		t.Errorf("time round-trip = %v, want %v", got, now)
	}

	codexClearMeta(auth, codexMetaDisabledReason, codexMetaDisabledUntil, codexMeta401Streak)
	if got := codexMetaString(auth, codexMetaDisabledReason); got != "" {
		t.Errorf("expected empty after clear, got %q", got)
	}
	if got := codexMetaInt(auth, codexMeta401Streak); got != 0 {
		t.Errorf("expected 0 after clear, got %d", got)
	}
}

func TestCodexMetaInt_IgnoresNonNumericValues(t *testing.T) {
	auth := &Auth{Metadata: map[string]any{codexMeta401Streak: "not-a-number"}}
	if got := codexMetaInt(auth, codexMeta401Streak); got != 0 {
		t.Errorf("non-numeric metadata must yield 0, got %d", got)
	}
}

// === markCodexQuotaDisabled / clearCodexQuotaDisabled ===

func TestMarkCodexQuotaDisabled_WritesAllFieldsAndFlipsDisabled(t *testing.T) {
	auth := &Auth{ID: "codex-1", Provider: codexProviderName}
	now := time.Now()
	retryAfter := 90 * time.Second
	cfg := defaultCodexGuardConfig()
	cfg.DisableOnQuotaExhausted = true

	if !markCodexQuotaDisabled(auth, cfg, &retryAfter, now) {
		t.Fatal("expected first-time disable to report a state change")
	}
	if !auth.Disabled || auth.Status != StatusDisabled {
		t.Fatalf("auth not marked disabled: Disabled=%v Status=%s", auth.Disabled, auth.Status)
	}
	if got := codexMetaString(auth, codexMetaDisabledReason); got != codexDisabledReasonQuota {
		t.Errorf("disabled_reason = %q, want %q", got, codexDisabledReasonQuota)
	}
	until := codexMetaTime(auth, codexMetaDisabledUntil)
	if until.IsZero() {
		t.Fatal("disabled_until missing when retryAfter provided in resets-at mode")
	}
	if delta := until.Sub(now.Add(retryAfter)); delta < -time.Second || delta > time.Second {
		t.Errorf("disabled_until off by %s", delta)
	}
}

func TestMarkCodexQuotaDisabled_ManualModeLeavesUntilEmpty(t *testing.T) {
	auth := &Auth{ID: "codex-1", Provider: codexProviderName}
	retryAfter := 90 * time.Second
	cfg := defaultCodexGuardConfig()
	cfg.DisableOnQuotaExhausted = true
	cfg.QuotaRecoveryMode = codexQuotaRecoveryManual

	if !markCodexQuotaDisabled(auth, cfg, &retryAfter, time.Now()) {
		t.Fatal("expected disable to report change")
	}
	if got := codexMetaString(auth, codexMetaDisabledUntil); got != "" {
		t.Errorf("manual mode must not write disabled_until, got %q", got)
	}
}

func TestMarkCodexQuotaDisabled_IdempotentOnRepeatedSameUntil(t *testing.T) {
	auth := &Auth{ID: "codex-1", Provider: codexProviderName}
	now := time.Now()
	retryAfter := 10 * time.Minute
	cfg := defaultCodexGuardConfig()
	cfg.DisableOnQuotaExhausted = true

	if !markCodexQuotaDisabled(auth, cfg, &retryAfter, now) {
		t.Fatal("expected first call to change state")
	}
	if markCodexQuotaDisabled(auth, cfg, &retryAfter, now) {
		t.Fatal("expected second call with identical inputs to be a no-op")
	}
}

func TestClearCodexQuotaDisabled_OnlyTouchesQuotaDisabledState(t *testing.T) {
	now := time.Now()
	cfg := defaultCodexGuardConfig()
	cfg.DisableOnQuotaExhausted = true

	auth := &Auth{ID: "codex-1", Provider: codexProviderName}
	retryAfter := time.Minute
	markCodexQuotaDisabled(auth, cfg, &retryAfter, now)
	if !clearCodexQuotaDisabled(auth, now.Add(2*time.Minute)) {
		t.Fatal("expected clear to report a state change")
	}
	if auth.Disabled || auth.Status == StatusDisabled {
		t.Fatalf("auth still marked disabled after clear: %+v", auth)
	}
	if got := codexMetaString(auth, codexMetaDisabledReason); got != "" {
		t.Errorf("metadata not cleared: %q", got)
	}

	// A credential disabled by an operator (no quota_exhausted reason) must
	// survive sweeper attention untouched.
	manual := &Auth{ID: "codex-2", Provider: codexProviderName, Disabled: true, Status: StatusDisabled}
	if clearCodexQuotaDisabled(manual, now) {
		t.Fatal("non-quota disabled auth must not be auto-recovered")
	}
}

func TestCodexQuotaDisabledExpired(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		auth *Auth
		want bool
	}{
		{name: "not_disabled", auth: &Auth{Provider: codexProviderName}, want: false},
		{
			name: "future_window",
			auth: &Auth{
				Provider: codexProviderName, Disabled: true,
				Metadata: map[string]any{
					codexMetaDisabledReason: codexDisabledReasonQuota,
					codexMetaDisabledUntil:  now.Add(time.Hour).UTC().Format(time.RFC3339),
				},
			},
			want: false,
		},
		{
			name: "past_window",
			auth: &Auth{
				Provider: codexProviderName, Disabled: true,
				Metadata: map[string]any{
					codexMetaDisabledReason: codexDisabledReasonQuota,
					codexMetaDisabledUntil:  now.Add(-time.Minute).UTC().Format(time.RFC3339),
				},
			},
			want: true,
		},
		{
			name: "manual_mode_no_until",
			auth: &Auth{
				Provider: codexProviderName, Disabled: true,
				Metadata: map[string]any{codexMetaDisabledReason: codexDisabledReasonQuota},
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := codexQuotaDisabledExpired(tc.auth, now); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// === streak counter ===

func TestBumpCodexUnauthorizedStreak_AccumulatesWithinWindow(t *testing.T) {
	auth := &Auth{ID: "codex-1"}
	now := time.Now()
	window := 5 * time.Minute

	if got := bumpCodexUnauthorizedStreak(auth, now, window); got != 1 {
		t.Errorf("first bump = %d, want 1", got)
	}
	if got := bumpCodexUnauthorizedStreak(auth, now.Add(2*time.Minute), window); got != 2 {
		t.Errorf("within-window bump = %d, want 2", got)
	}
	if got := bumpCodexUnauthorizedStreak(auth, now.Add(3*time.Minute), window); got != 3 {
		t.Errorf("within-window bump = %d, want 3", got)
	}
}

func TestBumpCodexUnauthorizedStreak_ResetsOnWindowExpiry(t *testing.T) {
	auth := &Auth{ID: "codex-1"}
	now := time.Now()
	window := 5 * time.Minute
	bumpCodexUnauthorizedStreak(auth, now, window)
	bumpCodexUnauthorizedStreak(auth, now.Add(time.Minute), window)

	// Skip past the window — counter must reset to 1.
	if got := bumpCodexUnauthorizedStreak(auth, now.Add(10*time.Minute), window); got != 1 {
		t.Errorf("after window expiry bump = %d, want 1", got)
	}
}

func TestBumpCodexUnauthorizedStreak_ZeroWindowDisablesReset(t *testing.T) {
	auth := &Auth{ID: "codex-1"}
	now := time.Now()
	bumpCodexUnauthorizedStreak(auth, now, 0)
	if got := bumpCodexUnauthorizedStreak(auth, now.Add(time.Hour), 0); got != 2 {
		t.Errorf("zero window must not reset streak, got %d", got)
	}
}

func TestClearCodexUnauthorizedStreak_IdempotentWhenEmpty(t *testing.T) {
	auth := &Auth{Metadata: map[string]any{}}
	if clearCodexUnauthorizedStreak(auth) {
		t.Fatal("expected no change when streak metadata absent")
	}
	auth.Metadata[codexMeta401Streak] = "3"
	auth.Metadata[codexMeta401LastAt] = time.Now().Format(time.RFC3339)
	if !clearCodexUnauthorizedStreak(auth) {
		t.Fatal("expected change when streak metadata present")
	}
	if _, ok := auth.Metadata[codexMeta401Streak]; ok {
		t.Fatal("streak key not removed")
	}
}

// === isCodex*  ===

func TestIsCodexClassifiers(t *testing.T) {
	if !isCodexAuth(&Auth{Provider: "codex"}) {
		t.Error("lowercase codex should classify")
	}
	if !isCodexAuth(&Auth{Provider: "Codex"}) {
		t.Error("mixed case codex should classify")
	}
	if isCodexAuth(&Auth{Provider: "claude"}) {
		t.Error("non-codex must not classify")
	}
	if isCodexAuth(nil) {
		t.Error("nil auth must not classify")
	}
	if !isCodexResult(Result{Provider: "codex"}) {
		t.Error("Result classification missed")
	}
}

// === deleteCodexAuthFile ===

// minimalStore is a no-op Store used to exercise deleteCodexAuthFile without
// pulling in postgres/git/filesystem backends. It records calls so the test
// can assert the store path was visited.
type minimalStore struct {
	mu     sync.Mutex
	saves  int
	delIDs []string
	delErr error
}

func (s *minimalStore) List(context.Context) ([]*Auth, error) { return nil, nil }
func (s *minimalStore) Save(_ context.Context, auth *Auth) (string, error) {
	s.mu.Lock()
	s.saves++
	s.mu.Unlock()
	return auth.ID, nil
}
func (s *minimalStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	s.delIDs = append(s.delIDs, id)
	s.mu.Unlock()
	return s.delErr
}

func TestDeleteCodexAuthFile_RemovesAcrossAllLayers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "codex-1.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	store := &minimalStore{}
	mgr := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "codex-1",
		Provider: codexProviderName,
		Attributes: map[string]string{
			AttributePath: path,
		},
	}
	mgr.auths[auth.ID] = auth

	if err := mgr.deleteCodexAuthFile(context.Background(), auth); err != nil {
		t.Fatalf("deleteCodexAuthFile: %v", err)
	}
	if _, errStat := os.Stat(path); !os.IsNotExist(errStat) {
		t.Errorf("file still present on disk: err=%v", errStat)
	}
	if len(store.delIDs) != 1 || store.delIDs[0] != auth.ID {
		t.Errorf("store.Delete not called with auth id, got %v", store.delIDs)
	}
	if _, ok := mgr.auths[auth.ID]; ok {
		t.Error("in-memory auth not removed")
	}
}

func TestDeleteCodexAuthFile_IdempotentOnMissingFile(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "gone.json")
	store := &minimalStore{}
	mgr := NewManager(store, nil, nil)
	auth := &Auth{
		ID:         "codex-2",
		Provider:   codexProviderName,
		Attributes: map[string]string{AttributePath: missing},
	}
	mgr.auths[auth.ID] = auth

	if err := mgr.deleteCodexAuthFile(context.Background(), auth); err != nil {
		t.Fatalf("expected no error when file is already gone, got: %v", err)
	}
}

// === sanity: streak integer serialization rounds through strconv ===

func TestStreakSerialization(t *testing.T) {
	for _, n := range []int{1, 3, 7, 42} {
		s := strconv.Itoa(n)
		auth := &Auth{Metadata: map[string]any{codexMeta401Streak: s}}
		if got := codexMetaInt(auth, codexMeta401Streak); got != n {
			t.Errorf("round-trip %d -> %q -> %d", n, s, got)
		}
	}
}
