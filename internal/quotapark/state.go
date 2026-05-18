package quotapark

import (
	"sync"
	"time"
)

// stateStore is the in-memory registry of currently parked auths. The watcher
// loses the auth from the active scheduler on rename, so this map is the only
// place that remembers a parked file once it is out of <authDir>.
type stateStore struct {
	mu      sync.RWMutex
	entries map[string]*ParkedInfo
}

func newStateStore() *stateStore {
	return &stateStore{entries: make(map[string]*ParkedInfo)}
}

// Get returns a copy of the parked entry for authID, if any.
func (s *stateStore) Get(authID string) (ParkedInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if info, ok := s.entries[authID]; ok && info != nil {
		return *info, true
	}
	return ParkedInfo{}, false
}

// Put inserts or replaces the entry for authID. The caller passes the entry by
// value to make the store the sole owner of the live pointer.
func (s *stateStore) Put(info ParkedInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := info
	s.entries[info.AuthID] = &copy
}

// Delete removes the entry for authID. Returns true if an entry existed.
func (s *stateStore) Delete(authID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[authID]; ok {
		delete(s.entries, authID)
		return true
	}
	return false
}

// Has reports whether authID is currently parked.
func (s *stateStore) Has(authID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.entries[authID]
	return ok
}

// Snapshot returns a sorted-stable copy of all parked entries.
func (s *stateStore) Snapshot() []ParkedInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ParkedInfo, 0, len(s.entries))
	for _, info := range s.entries {
		if info != nil {
			out = append(out, *info)
		}
	}
	return out
}

// Update applies fn to the stored entry for authID. fn receives a pointer to
// the live struct (not a copy) so callers can mutate fields directly. fn is
// invoked under the write lock; do NOT call back into stateStore from fn.
func (s *stateStore) Update(authID string, fn func(*ParkedInfo)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.entries[authID]
	if !ok || info == nil {
		return false
	}
	fn(info)
	return true
}

// Len reports the number of parked entries.
func (s *stateStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// dueForProbe returns parked entries whose next probe is due relative to now.
func (s *stateStore) dueForProbe(now time.Time, defaultInterval time.Duration) []ParkedInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var due []ParkedInfo
	for _, info := range s.entries {
		if info == nil {
			continue
		}
		interval := info.CurrentProbeInterval
		if interval <= 0 {
			interval = defaultInterval
		}
		if info.LastProbeAt.IsZero() || !now.Before(info.LastProbeAt.Add(interval)) {
			due = append(due, *info)
		}
	}
	return due
}
