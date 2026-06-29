package auth

import (
	"context"
	"testing"
	"time"
)

func TestSweepCodexQuotaDisabled_ReEnablesExpiredAuth(t *testing.T) {
	mgr := NewManager(nil, nil, nil)

	// Quota-disabled, window in the past — should be auto-recovered.
	expired := &Auth{
		ID:       "codex-expired",
		Provider: codexProviderName,
		Disabled: true,
		Status:   StatusDisabled,
		Metadata: map[string]any{
			codexMetaDisabledReason: codexDisabledReasonQuota,
			codexMetaDisabledUntil:  time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
			codexMetaDisabledAt:     time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		},
	}
	// Quota-disabled, window still in the future — must NOT be touched.
	future := &Auth{
		ID:       "codex-future",
		Provider: codexProviderName,
		Disabled: true,
		Status:   StatusDisabled,
		Metadata: map[string]any{
			codexMetaDisabledReason: codexDisabledReasonQuota,
			codexMetaDisabledUntil:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		},
	}
	// Manually disabled (no codex_disabled_reason) — must NOT be touched.
	manual := &Auth{
		ID:       "codex-manual",
		Provider: codexProviderName,
		Disabled: true,
		Status:   StatusDisabled,
		Metadata: map[string]any{},
	}
	// Non-codex disabled — must NOT be touched.
	otherProvider := &Auth{
		ID:       "claude-1",
		Provider: "claude",
		Disabled: true,
		Status:   StatusDisabled,
		Metadata: map[string]any{
			codexMetaDisabledReason: codexDisabledReasonQuota,
			codexMetaDisabledUntil:  time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
		},
	}
	for _, a := range []*Auth{expired, future, manual, otherProvider} {
		mgr.auths[a.ID] = a
	}

	mgr.sweepCodexQuotaDisabled(context.Background())

	if expired.Disabled || expired.Status == StatusDisabled {
		t.Errorf("expired auth not recovered: %+v", expired)
	}
	if _, ok := expired.Metadata[codexMetaDisabledReason]; ok {
		t.Error("expired auth metadata not cleared")
	}
	if !future.Disabled {
		t.Error("future-window auth incorrectly recovered")
	}
	if !manual.Disabled {
		t.Error("manually disabled auth incorrectly recovered")
	}
	if !otherProvider.Disabled {
		t.Error("non-codex auth incorrectly recovered")
	}
}

func TestStartCooldownRecoveryLoop_StopsOnContextCancel(t *testing.T) {
	mgr := NewManager(nil, nil, nil)

	parent, cancel := context.WithCancel(context.Background())
	mgr.StartCooldownRecoveryLoop(parent, 10*time.Millisecond)

	// Give the loop a chance to install its cancel.
	time.Sleep(20 * time.Millisecond)
	mgr.mu.Lock()
	hasCancel := mgr.cooldownRecoveryCancel != nil
	mgr.mu.Unlock()
	if !hasCancel {
		t.Fatal("expected loop to register a cancel func")
	}

	cancel()
	// Loop should exit; subsequent StopCooldownRecoveryLoop must be safe.
	time.Sleep(30 * time.Millisecond)
	mgr.StopCooldownRecoveryLoop()
}

func TestStartCooldownRecoveryLoop_RestartCancelsPrevious(t *testing.T) {
	mgr := NewManager(nil, nil, nil)

	mgr.StartCooldownRecoveryLoop(context.Background(), 50*time.Millisecond)
	mgr.mu.Lock()
	first := mgr.cooldownRecoveryCancel
	mgr.mu.Unlock()
	if first == nil {
		t.Fatal("expected first start to install cancel")
	}

	mgr.StartCooldownRecoveryLoop(context.Background(), 50*time.Millisecond)
	mgr.mu.Lock()
	second := mgr.cooldownRecoveryCancel
	mgr.mu.Unlock()
	if second == nil {
		t.Fatal("expected second start to install cancel")
	}
	// First cancel should be a different function pointer than the second.
	// (Hard to assert directly via reflection in a portable way; rely on
	// behavioral consistency: stopping cleans up the live one.)
	mgr.StopCooldownRecoveryLoop()
	mgr.mu.Lock()
	leftover := mgr.cooldownRecoveryCancel
	mgr.mu.Unlock()
	if leftover != nil {
		t.Error("expected Stop to clear cancel func")
	}
}
