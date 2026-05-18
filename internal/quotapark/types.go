// Package quotapark implements automatic quarantine and probe-based recovery
// for OAuth auth files (currently codex only) that repeatedly receive HTTP 429.
//
// When the conductor's Hook reports an OnQuotaExceeded for an authID, the
// Tracker counts the hit. If the configured threshold is exceeded inside the
// rolling window, the Mover renames the file from <authDir>/<id>.json to
// <authDir>/<parkDir>/<id>.json. The existing file watcher detects the rename
// and unregisters the auth from the active scheduler.
//
// A background Prober periodically reads each parked JSON file, refreshes its
// OAuth token, and sends a minimal real inference request to the upstream.
// On HTTP 2xx the file is renamed back into the active dir; on 429 it stays
// parked. Other errors keep the file parked and bump consecutive failure
// counters so the prober throttles itself.
package quotapark

import (
	"context"
	"time"
)

// ProbeResult captures the outcome of a single probe attempt.
type ProbeResult int

const (
	// ProbeUnknown indicates an unset result.
	ProbeUnknown ProbeResult = iota
	// ProbeRecovered means the upstream returned 2xx; the auth should be unparked.
	ProbeRecovered
	// ProbeStillExhausted means the upstream returned 429; keep the auth parked.
	ProbeStillExhausted
	// ProbeAuthError means the upstream returned 401/403 after a successful token
	// refresh, suggesting a credential problem rather than a transient quota issue.
	ProbeAuthError
	// ProbeError means the probe attempt failed for an unrelated reason (network,
	// refresh failure, malformed JSON, etc.); the auth stays parked.
	ProbeError
	// ProbeSkipUnsupported means the probe was skipped because the auth's
	// provider is not supported by this implementation.
	ProbeSkipUnsupported
)

// String returns a stable label for log fields.
func (r ProbeResult) String() string {
	switch r {
	case ProbeRecovered:
		return "recovered"
	case ProbeStillExhausted:
		return "still_429"
	case ProbeAuthError:
		return "auth_error"
	case ProbeError:
		return "error"
	case ProbeSkipUnsupported:
		return "unsupported"
	default:
		return "unknown"
	}
}

// ParkedInfo records the runtime state for a single parked auth file.
type ParkedInfo struct {
	AuthID          string
	OriginalAbsPath string
	ParkedAbsPath   string
	Provider        string
	ParkedAt        time.Time
	LastProbeAt     time.Time
	LastProbeResult ProbeResult
	LastProbeErr    string
	// ConsecutiveProbeFailures counts non-2xx non-429 outcomes since the last
	// successful or 429 probe. Used to back off the probe interval.
	ConsecutiveProbeFailures int
	// ConsecutivePostUnparkParks counts how many times this auth was unparked
	// then re-parked without a healthy interval in between. Used for backoff.
	ConsecutivePostUnparkParks int
	// CurrentProbeInterval is the effective interval for this auth's next probe.
	CurrentProbeInterval time.Duration
}

// ProbeFunc is the contract implemented by per-provider probes. Implementations
// must respect ctx cancellation and must classify the outcome into one of the
// ProbeResult values. The returned error is informational (logged) and never
// implies a particular ProbeResult.
type ProbeFunc func(ctx context.Context, info ParkedInfo) (ProbeResult, error)
