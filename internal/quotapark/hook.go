package quotapark

import (
	"context"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// Hook bridges the conductor's coreauth.Hook interface to the Service. It is
// a thin adapter that delegates to Service methods and ignores all other hook
// events (auth lifecycle, generic results) by no-op.
type Hook struct {
	svc *Service
}

var _ coreauth.Hook = (*Hook)(nil)

// OnAuthRegistered implements coreauth.Hook.
func (h *Hook) OnAuthRegistered(context.Context, *coreauth.Auth) {}

// OnAuthUpdated implements coreauth.Hook.
func (h *Hook) OnAuthUpdated(context.Context, *coreauth.Auth) {}

// OnResult implements coreauth.Hook.
func (h *Hook) OnResult(context.Context, coreauth.Result) {}

// OnQuotaExceeded implements coreauth.Hook.
func (h *Hook) OnQuotaExceeded(_ context.Context, authID, provider, model string, at time.Time) {
	if h == nil || h.svc == nil {
		return
	}
	h.svc.observe429(authID, provider, model, at)
}

// OnAuthSuccess implements coreauth.Hook.
func (h *Hook) OnAuthSuccess(_ context.Context, authID string) {
	if h == nil || h.svc == nil {
		return
	}
	h.svc.markSuccess(authID)
}
