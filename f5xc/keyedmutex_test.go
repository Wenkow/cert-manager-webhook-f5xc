package f5xc

import (
	"sync"
	"testing"
	"time"
)

// Mutual exclusion: many goroutines incrementing a shared int under the same key
// must not race; the final value must equal the number of increments.
func TestKeyedMutex_MutualExclusion(t *testing.T) {
	var km keyedMutex
	const n = 200
	counter := 0
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			km.Lock("k")
			counter++ // non-atomic on purpose; the lock must protect it
			km.Unlock("k")
		}()
	}
	wg.Wait()
	if counter != n {
		t.Fatalf("counter = %d, want %d (lost updates => lock not exclusive)", counter, n)
	}
	if got := km.len(); got != 0 {
		t.Fatalf("entries leaked: len = %d, want 0", got)
	}
}

// Independence: holding one key must not block a different key.
func TestKeyedMutex_DifferentKeysDoNotBlock(t *testing.T) {
	var km keyedMutex
	km.Lock("a")
	defer km.Unlock("a")

	done := make(chan struct{})
	go func() {
		km.Lock("b")
		km.Unlock("b")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("locking key b blocked while key a was held")
	}
}

// No leak after balanced lock/unlock on many distinct keys.
func TestKeyedMutex_NoLeak(t *testing.T) {
	var km keyedMutex
	for i := 0; i < 100; i++ {
		k := string(rune('a' + i%26))
		km.Lock(k)
		km.Unlock(k)
	}
	if got := km.len(); got != 0 {
		t.Fatalf("entries leaked: len = %d, want 0", got)
	}
}
