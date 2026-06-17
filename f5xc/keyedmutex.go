package f5xc

import "sync"

// keyedMutex provides per-key mutual exclusion. Its zero value is ready to use,
// so a Solver can embed it by value. Entries are reference-counted and removed
// when the last holder releases, so the internal map does not grow without bound
// across many distinct keys (e.g. one per challenge FQDN).
type keyedMutex struct {
	mu      sync.Mutex
	entries map[string]*keyedMutexEntry
}

type keyedMutexEntry struct {
	mu       sync.Mutex
	refcount int
}

// Lock acquires the lock for key, blocking until it is available.
func (k *keyedMutex) Lock(key string) {
	k.mu.Lock()
	if k.entries == nil {
		k.entries = make(map[string]*keyedMutexEntry)
	}
	e := k.entries[key]
	if e == nil {
		e = &keyedMutexEntry{}
		k.entries[key] = e
	}
	e.refcount++
	k.mu.Unlock()

	e.mu.Lock()
}

// Unlock releases the lock for key. It must pair with a prior Lock(key).
//
// The per-key mutex is released BEFORE the refcount is decremented and the entry
// possibly deleted. Doing it in the other order is racy: a deletion could let a
// new caller create a fresh entry and enter the critical section while this
// caller still holds the old per-key mutex.
func (k *keyedMutex) Unlock(key string) {
	k.mu.Lock()
	e := k.entries[key]
	k.mu.Unlock()
	if e == nil {
		panic("keyedMutex: Unlock of unlocked key " + key)
	}

	e.mu.Unlock()

	k.mu.Lock()
	e.refcount--
	if e.refcount == 0 {
		delete(k.entries, key)
	}
	k.mu.Unlock()
}

// len reports the number of live entries. Test-only.
func (k *keyedMutex) len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.entries)
}
