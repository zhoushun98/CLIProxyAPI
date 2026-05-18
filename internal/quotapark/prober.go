package quotapark

import (
	"context"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// proberBaseInterval lower bound for the periodic tick. Real interval comes
	// from cfg.QuotaPark.Probe.Interval; tickPeriod just controls how often the
	// goroutine wakes up to scan the parked set.
	proberMinTick = 1 * time.Second

	// proberMaxBackoff caps the per-auth backoff after repeated probe failures
	// or post-unpark bounces.
	proberMaxBackoff = 2 * time.Hour

	// proberFailureSwitch threshold at which the probe interval is raised to
	// proberFailureLongInterval to stop hammering an upstream that keeps erroring.
	proberFailureSwitch       = 12
	proberFailureLongInterval = 30 * time.Minute
)

// prober owns the background goroutine that probes parked auths.
type prober struct {
	state    *stateStore
	tracker  *tracker
	mover    *mover
	probeFn  ProbeFunc
	interval atomic.Int64 // configured probe interval (nanoseconds)
}

func newProber(state *stateStore, trk *tracker, mv *mover, fn ProbeFunc, defaultInterval time.Duration) *prober {
	p := &prober{state: state, tracker: trk, mover: mv, probeFn: fn}
	if defaultInterval <= 0 {
		defaultInterval = 5 * time.Minute
	}
	p.interval.Store(int64(defaultInterval))
	return p
}

// SetInterval updates the default probe interval. Per-auth backoff overrides
// are stored on each ParkedInfo and are not touched by this call.
func (p *prober) SetInterval(d time.Duration) {
	if d <= 0 {
		return
	}
	p.interval.Store(int64(d))
}

// run loops until ctx is cancelled. Each tick scans parked entries and probes
// any whose next probe is due. The scan tick is min(interval, 30s) so a long
// default interval still allows quick reaction when the operator adds entries.
func (p *prober) run(ctx context.Context) {
	tick := p.scanTick()
	timer := time.NewTimer(tick)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			p.runOnce(ctx)
			timer.Reset(p.scanTick())
		}
	}
}

func (p *prober) scanTick() time.Duration {
	d := time.Duration(p.interval.Load())
	if d <= 0 {
		d = 5 * time.Minute
	}
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	if d < proberMinTick {
		d = proberMinTick
	}
	return d
}

// runOnce performs one scan-and-probe pass. Returned slice of authIDs is for
// test inspection only.
func (p *prober) runOnce(ctx context.Context) []string {
	now := time.Now()
	defaultInterval := time.Duration(p.interval.Load())
	due := p.state.dueForProbe(now, defaultInterval)
	probed := make([]string, 0, len(due))

	for _, info := range due {
		select {
		case <-ctx.Done():
			return probed
		default:
		}
		probed = append(probed, info.AuthID)
		result, err := p.probeFn(ctx, info)
		p.applyResult(info.AuthID, result, err, defaultInterval)
	}
	return probed
}

// applyResult updates state and (optionally) triggers an unpark based on the
// probe outcome.
func (p *prober) applyResult(authID string, result ProbeResult, probeErr error, defaultInterval time.Duration) {
	now := time.Now()

	switch result {
	case ProbeRecovered:
		// Unpark the file. The watcher will pick up the rename and re-register
		// the auth with the conductor.
		dst, errUnpark := p.mover.Unpark(authID)
		if errUnpark != nil {
			log.WithFields(log.Fields{"auth_id": authID, "err": errUnpark.Error()}).Warn("quota-park: unpark failed |")
			// Stash the failure on the entry so it does not loop tightly.
			p.state.Update(authID, func(info *ParkedInfo) {
				info.LastProbeAt = now
				info.LastProbeResult = result
				info.LastProbeErr = errUnpark.Error()
			})
			return
		}
		p.tracker.StartGrace(authID, now)
		p.state.Delete(authID)
		log.WithFields(log.Fields{"auth_id": authID, "path": dst}).Info("quota-park: unparking |")
		return

	case ProbeStillExhausted:
		p.state.Update(authID, func(info *ParkedInfo) {
			info.LastProbeAt = now
			info.LastProbeResult = result
			info.LastProbeErr = ""
			info.ConsecutiveProbeFailures = 0
			if info.CurrentProbeInterval <= 0 {
				info.CurrentProbeInterval = defaultInterval
			}
		})
		log.WithFields(log.Fields{"auth_id": authID}).Debug("quota-park: probe still-429 |")
		return

	case ProbeAuthError:
		msg := ""
		if probeErr != nil {
			msg = probeErr.Error()
		}
		p.state.Update(authID, func(info *ParkedInfo) {
			info.LastProbeAt = now
			info.LastProbeResult = result
			info.LastProbeErr = msg
			info.ConsecutiveProbeFailures++
			info.CurrentProbeInterval = nextBackoff(info, defaultInterval)
		})
		log.WithFields(log.Fields{"auth_id": authID, "err": msg}).Warn("quota-park: probe auth-error |")
		return

	case ProbeSkipUnsupported:
		p.state.Update(authID, func(info *ParkedInfo) {
			info.LastProbeAt = now
			info.LastProbeResult = result
			info.LastProbeErr = "unsupported provider"
			info.CurrentProbeInterval = proberFailureLongInterval
		})
		log.WithFields(log.Fields{"auth_id": authID, "provider": authProvider(p.state, authID)}).Debug("quota-park: probe unsupported provider, parked indefinitely |")
		return

	default: // ProbeError, ProbeUnknown
		msg := ""
		if probeErr != nil {
			msg = probeErr.Error()
		}
		p.state.Update(authID, func(info *ParkedInfo) {
			info.LastProbeAt = now
			info.LastProbeResult = result
			info.LastProbeErr = msg
			info.ConsecutiveProbeFailures++
			info.CurrentProbeInterval = nextBackoff(info, defaultInterval)
		})
		log.WithFields(log.Fields{"auth_id": authID, "err": msg}).Warn("quota-park: probe error |")
	}
}

// nextBackoff returns the probe interval to use for the *next* probe, given
// the entry's accumulated failure counts. The current entry is read by the
// caller before invoking nextBackoff under the state lock.
func nextBackoff(info *ParkedInfo, defaultInterval time.Duration) time.Duration {
	if info.ConsecutiveProbeFailures >= proberFailureSwitch {
		return proberFailureLongInterval
	}
	if info.ConsecutivePostUnparkParks > 3 {
		// Exponential back off the post-unpark bounce: 2x, 4x, 8x... capped.
		mult := time.Duration(1)
		for i := 0; i < info.ConsecutivePostUnparkParks-3 && mult < 16; i++ {
			mult *= 2
		}
		d := defaultInterval * mult
		if d > proberMaxBackoff {
			d = proberMaxBackoff
		}
		return d
	}
	return defaultInterval
}

// authProvider returns the provider name for authID, or "" if not known.
func authProvider(state *stateStore, authID string) string {
	info, ok := state.Get(authID)
	if !ok {
		return ""
	}
	return info.Provider
}
