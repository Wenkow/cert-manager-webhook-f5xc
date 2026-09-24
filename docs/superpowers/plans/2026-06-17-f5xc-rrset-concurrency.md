# F5 XC RRSet Concurrency Safety Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `Present`/`CleanUp` safe against lost updates when many certificates are issued at once, by serializing the shared-RRSet read-modify-write per FQDN and verifying each write landed.

**Architecture:** A refcounted per-FQDN keyed mutex (zero-value usable, lives on `Solver`) serializes the GET→modify→write cycle. A unified reconcile loop parameterized by `satisfied`/`mutate` drives both `Present` and `CleanUp`, re-reading after each write (the read-back) and re-applying idempotently up to a bound. The F5 XC client is unchanged.

**Tech Stack:** Go, `sync` (mutex), `k8s.io/klog/v2`, cert-manager webhook solver interface. Tests: standard `testing`, `-race`. Lint: golangci-lint v2.13.2 (staticcheck + typecheck) — must match the pin in `.github/workflows/ci.yaml`, and its build Go must be >= the `go` directive in `go.mod`.

---

## Spec

Design spec: `docs/superpowers/specs/2026-06-17-f5xc-rrset-concurrency-design.md`.

## File Structure

- **Create** `f5xc/keyedmutex.go` — `keyedMutex`: per-key mutual exclusion, refcounted, zero-value usable. Single responsibility: locking.
- **Create** `f5xc/keyedmutex_test.go` — unit tests for `keyedMutex` (exclusion, independence, no leak), run under `-race`.
- **Modify** `f5xc/solver.go` — add `locks keyedMutex` field to `Solver`; add `verifyAttempts`/`verifyInterval` vars; add `rrsetOp` type, `lockKey`/`currentValues`/`containsValue` helpers and the `reconcile` method; rewrite `Present`/`CleanUp` to delegate to `reconcile`.
- **Modify** `f5xc/solver_test.go` — add a stateful in-memory `fakeRRSetClient` and a `fastReconcile` helper; repoint existing `Present`/`CleanUp` tests onto the fake; add read-back retry, exhaustion, and the headline lost-update concurrency tests.
- **Modify** `f5xc/integration_p12_test.go` (gitignored, build tag `integration`) — add a live concurrent-`Present` scenario.

## Conventions (match existing code)

- Errors: `fmt.Errorf("f5xc: ...: %w", err)`.
- Logging: `klog.V(2).InfoS("f5xc: ...", "k", v)`.
- Not-found detection: `client.IsNotFound(err)`.
- TTL: `cfg.EffectiveTTL()`.
- Run a single package: `go test ./f5xc/ -run <Name> -v`. Race: `go test -race ./f5xc/ -run <Name>`.

---

## Task 1: keyedMutex

**Files:**
- Create: `f5xc/keyedmutex.go`
- Test: `f5xc/keyedmutex_test.go`

- [x] **Step 1: Write the failing tests**

Create `f5xc/keyedmutex_test.go`:

```go
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
```

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./f5xc/ -run TestKeyedMutex -v`
Expected: FAIL — compile error `undefined: keyedMutex`.

- [x] **Step 3: Write the implementation**

Create `f5xc/keyedmutex.go`:

```go
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
```

- [x] **Step 4: Run tests (with race detector) to verify they pass**

Run: `go test -race ./f5xc/ -run TestKeyedMutex -v`
Expected: PASS (all three), no race warnings.

- [x] **Step 5: Commit**

```bash
git add f5xc/keyedmutex.go f5xc/keyedmutex_test.go
git commit -m "feat: add refcounted per-key mutex for RRSet serialization"
```

---

## Task 2: Stateful fake client + test helpers

This introduces the test backbone the reconcile tests need. The existing closure-based `mockClient` returns fixed values and cannot model read-after-write, so the read-back loop needs a fake whose GET reflects prior writes.

**Files:**
- Modify: `f5xc/solver_test.go` (add fake + helpers + a sanity test)

- [x] **Step 1: Add the stateful fake and helpers, plus a sanity test**

Append to `f5xc/solver_test.go` (keep existing `mockClient`, `challengeRequest`, `fakeSecretReader`, etc.):

```go
// fakeRRSetClient is an in-memory RRSetClient whose GET reflects prior writes,
// so it can model F5 XC's read-modify-write semantics for the reconcile loop.
// It is safe for concurrent use. Records are keyed by record name (tests use a
// single zone/group, all TXT).
type fakeRRSetClient struct {
	mu       sync.Mutex
	records  map[string]client.RRSet // name -> rrset
	creates  int
	replaces int
	deletes  int
	gets     int
	// loseWrites silently drops this many upcoming Create/Replace/Delete calls
	// (they return success but do not change state) to simulate a lost/lagging write.
	loseWrites int
}

func newFakeRRSetClient() *fakeRRSetClient {
	return &fakeRRSetClient{records: map[string]client.RRSet{}}
}

func (f *fakeRRSetClient) GetRRSet(_ context.Context, _, _, name, _ string) (*client.APIRRSet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	rr, ok := f.records[name]
	if !ok {
		return nil, nil // not found, mirrors client.GetRRSet
	}
	// return a deep copy so callers cannot mutate our state
	vals := append([]string{}, rr.TXTRecord.Values...)
	return &client.APIRRSet{RRSet: client.RRSet{
		TTL:       rr.TTL,
		TXTRecord: &client.TXTRecord{Name: rr.TXTRecord.Name, Values: vals},
	}}, nil
}

func (f *fakeRRSetClient) CreateRRSet(_ context.Context, _, _ string, rrset client.RRSet) (*client.APIRRSet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates++
	if f.loseWrites > 0 {
		f.loseWrites--
		return &client.APIRRSet{}, nil
	}
	f.records[rrset.TXTRecord.Name] = rrset
	return &client.APIRRSet{}, nil
}

func (f *fakeRRSetClient) ReplaceRRSet(_ context.Context, _, _, name, _ string, rrset client.RRSet) (*client.APIRRSet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replaces++
	if f.loseWrites > 0 {
		f.loseWrites--
		return &client.APIRRSet{}, nil
	}
	f.records[name] = rrset
	return &client.APIRRSet{}, nil
}

func (f *fakeRRSetClient) DeleteRRSet(_ context.Context, _, _, name, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes++
	if f.loseWrites > 0 {
		f.loseWrites--
		return nil
	}
	delete(f.records, name)
	return nil
}

// values returns the stored TXT values for a record name (nil if absent).
func (f *fakeRRSetClient) values(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	rr, ok := f.records[name]
	if !ok {
		return nil
	}
	return append([]string{}, rr.TXTRecord.Values...)
}

// fakeSolver builds a Solver backed by the given fake client and a token-auth secret.
func fakeSolver(fc *fakeRRSetClient) *Solver {
	return &Solver{
		clientFactory: func(cfg *F5XCConfig, auth client.Authenticator) (RRSetClient, error) { return fc, nil },
		secretReader:  &fakeSecretReader{data: map[string][]byte{"api-token": []byte("test-token")}},
	}
}

// fastReconcile makes the reconcile loop run without real backoff for the duration
// of a test. Tests using it must NOT call t.Parallel() (it mutates package vars).
func fastReconcile(t *testing.T) {
	t.Helper()
	oldInterval, oldAttempts := verifyInterval, verifyAttempts
	verifyInterval = 0
	verifyAttempts = 3
	t.Cleanup(func() { verifyInterval, verifyAttempts = oldInterval, oldAttempts })
}

func TestFakeRRSetClient_Sanity(t *testing.T) {
	fc := newFakeRRSetClient()
	ctx := context.Background()
	if rr, _ := fc.GetRRSet(ctx, "z", "g", "n", "TXT"); rr != nil {
		t.Fatal("expected nil for absent record")
	}
	_, _ = fc.CreateRRSet(ctx, "z", "g", client.RRSet{TXTRecord: &client.TXTRecord{Name: "n", Values: []string{"a"}}})
	if got := fc.values("n"); len(got) != 1 || got[0] != "a" {
		t.Fatalf("after create, values = %v, want [a]", got)
	}
	_, _ = fc.ReplaceRRSet(ctx, "z", "g", "n", "TXT", client.RRSet{TXTRecord: &client.TXTRecord{Name: "n", Values: []string{"a", "b"}}})
	if got := fc.values("n"); len(got) != 2 {
		t.Fatalf("after replace, values = %v, want 2", got)
	}
	_ = fc.DeleteRRSet(ctx, "z", "g", "n", "TXT")
	if got := fc.values("n"); got != nil {
		t.Fatalf("after delete, values = %v, want nil", got)
	}
}
```

Note: `solver_test.go` must import `sync`. Add it to the import block.

- [x] **Step 2: Run the sanity test to verify it fails**

Run: `go test ./f5xc/ -run TestFakeRRSetClient_Sanity -v`
Expected: FAIL — compile error `undefined: verifyInterval` / `undefined: verifyAttempts` (referenced by `fastReconcile`).

- [x] **Step 3: Add the package vars so the test file compiles**

In `f5xc/solver.go`, add `"time"` to the import block, and add these package-level vars after the imports (above `type RRSetClient`):

```go
// Reconcile/verification tuning. Vars (not consts) so tests can override them.
var (
	verifyAttempts = 5
	verifyInterval = time.Second
)
```

- [x] **Step 4: Run the sanity test to verify it passes**

Run: `go test ./f5xc/ -run TestFakeRRSetClient_Sanity -v`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add f5xc/solver_test.go f5xc/solver.go
git commit -m "test: add stateful fake RRSet client and reconcile tuning vars"
```

---

## Task 3: Reconcile loop + Present

**Files:**
- Modify: `f5xc/solver.go` (add `locks` field, `rrsetOp`, helpers, `reconcile`; rewrite `Present`)
- Modify: `f5xc/solver_test.go` (repoint Present tests onto the fake; add read-back + exhaustion tests)

- [ ] **Step 1: Write the failing Present tests (on the fake)**

In `f5xc/solver_test.go`, REPLACE the existing `TestSolver_Present_NewRecord` and `TestSolver_Present_AppendToExisting` and `TestSolver_Present_DuplicateValue` with these fake-backed versions, and add the read-back/exhaustion tests:

```go
func TestSolver_Present_NewRecord(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	ch := f5xcChallenge("challenge-key")
	if err := fakeSolver(fc).Present(ch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := fc.values("_acme-challenge"); len(got) != 1 || got[0] != "challenge-key" {
		t.Fatalf("values = %v, want [challenge-key]", got)
	}
	if fc.creates != 1 {
		t.Errorf("creates = %d, want 1", fc.creates)
	}
}

func TestSolver_Present_AppendToExisting(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	fc.records["_acme-challenge"] = client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"existing-value"}}}
	if err := fakeSolver(fc).Present(f5xcChallenge("new-value")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := fc.values("_acme-challenge")
	if len(got) != 2 || got[0] != "existing-value" || got[1] != "new-value" {
		t.Fatalf("values = %v, want [existing-value new-value]", got)
	}
}

func TestSolver_Present_DuplicateValue(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	fc.records["_acme-challenge"] = client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"challenge-key"}}}
	if err := fakeSolver(fc).Present(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fc.creates != 0 || fc.replaces != 0 {
		t.Errorf("no write expected for duplicate; creates=%d replaces=%d", fc.creates, fc.replaces)
	}
	if got := fc.values("_acme-challenge"); len(got) != 1 {
		t.Fatalf("values = %v, want exactly [challenge-key]", got)
	}
}

// First write is silently lost; the read-back must detect the value is missing and
// re-apply, converging without error.
func TestSolver_Present_ReadBackRecoversLostWrite(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	fc.loseWrites = 1 // drop the first create
	if err := fakeSolver(fc).Present(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := fc.values("_acme-challenge"); len(got) != 1 || got[0] != "challenge-key" {
		t.Fatalf("value did not converge; values = %v", got)
	}
	if fc.creates < 2 {
		t.Errorf("expected at least 2 create attempts (one lost), got %d", fc.creates)
	}
}

// Every write is lost; Present must error after verifyAttempts rather than hang.
func TestSolver_Present_ErrorsWhenNeverConverges(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	fc.loseWrites = 1000 // drop them all
	err := fakeSolver(fc).Present(f5xcChallenge("challenge-key"))
	if err == nil {
		t.Fatal("expected error when value never converges")
	}
	if fc.creates != verifyAttempts {
		t.Errorf("create attempts = %d, want %d", fc.creates, verifyAttempts)
	}
}
```

- [ ] **Step 2: Run the Present tests to verify they fail**

Run: `go test ./f5xc/ -run 'TestSolver_Present' -v`
Expected: FAIL — the new behavior (read-back, exhaustion error, exact write counts) is not implemented; counts/convergence assertions fail.

- [ ] **Step 3: Implement the reconcile loop, helpers, locks field, and rewrite Present**

In `f5xc/solver.go`:

(a) Add the `locks` field to `Solver`:

```go
// Solver implements the cert-manager webhook.Solver interface for F5 XC DNS.
type Solver struct {
	clientFactory clientFactory
	secretReader  SecretReader
	locks         keyedMutex // per-FQDN serialization; zero value is ready to use
}
```

(b) Add helpers and the reconcile machinery (place after `setup`, before `unFQDN`):

```go
// rrsetOp is the write needed to move an RRSet toward the desired state.
type rrsetOp int

const (
	opCreate rrsetOp = iota
	opReplace
	opDelete
)

// lockKey identifies a single RRSet (all records here are TXT).
func lockKey(zone, group, subdomain string) string {
	return zone + "/" + group + "/" + subdomain + "/TXT"
}

// currentValues extracts the TXT values from a GET result (nil when absent).
func currentValues(existing *client.APIRRSet) []string {
	if existing == nil || existing.RRSet.TXTRecord == nil {
		return nil
	}
	return existing.RRSet.TXTRecord.Values
}

func containsValue(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// reconcile serializes the read-modify-write for one RRSet (per FQDN) and verifies
// the result by reading back. Each iteration: GET, return if satisfied (this is the
// read-back), otherwise apply mutate. Re-application is safe because every operation
// is idempotent. Bounded by verifyAttempts; on exhaustion it returns an error so
// cert-manager retries the challenge.
func (s *Solver) reconcile(
	ctx context.Context,
	cl RRSetClient,
	cfg *F5XCConfig,
	zone, subdomain string,
	satisfied func(values []string) bool,
	mutate func(existing *client.APIRRSet) (rrsetOp, client.RRSet),
) error {
	key := lockKey(zone, cfg.GroupName, subdomain)
	s.locks.Lock(key)
	defer s.locks.Unlock(key)

	for attempt := 1; attempt <= verifyAttempts; attempt++ {
		existing, err := cl.GetRRSet(ctx, zone, cfg.GroupName, subdomain, "TXT")
		if err != nil {
			if !client.IsNotFound(err) {
				return fmt.Errorf("f5xc: getting RRSet: %w", err)
			}
			existing = nil
		}

		if satisfied(currentValues(existing)) {
			return nil
		}

		op, rrset := mutate(existing)
		switch op {
		case opCreate:
			if _, err := cl.CreateRRSet(ctx, zone, cfg.GroupName, rrset); err != nil {
				return fmt.Errorf("f5xc: creating RRSet: %w", err)
			}
		case opReplace:
			if _, err := cl.ReplaceRRSet(ctx, zone, cfg.GroupName, subdomain, "TXT", rrset); err != nil {
				return fmt.Errorf("f5xc: replacing RRSet: %w", err)
			}
		case opDelete:
			if err := cl.DeleteRRSet(ctx, zone, cfg.GroupName, subdomain, "TXT"); err != nil && !client.IsNotFound(err) {
				return fmt.Errorf("f5xc: deleting RRSet: %w", err)
			}
		}

		if attempt < verifyAttempts {
			time.Sleep(verifyInterval)
		}
	}

	return fmt.Errorf("f5xc: RRSet %q did not converge after %d attempts", subdomain, verifyAttempts)
}
```

(c) Rewrite `Present` (replace the whole existing `Present` func):

```go
// Present creates or appends a TXT record for the ACME challenge. It is idempotent
// and safe under concurrent challenges for the same FQDN.
func (s *Solver) Present(ch *acme.ChallengeRequest) error {
	cfg, cl, err := s.setup(ch)
	if err != nil {
		return err
	}

	ctx := context.Background()
	zone := unFQDN(ch.ResolvedZone)
	subdomain := extractSubDomain(ch.ResolvedFQDN, ch.ResolvedZone)

	klog.V(2).InfoS("f5xc: presenting challenge", "fqdn", ch.ResolvedFQDN, "zone", zone, "subdomain", subdomain)

	satisfied := func(values []string) bool {
		return containsValue(values, ch.Key)
	}
	mutate := func(existing *client.APIRRSet) (rrsetOp, client.RRSet) {
		if existing == nil || existing.RRSet.TXTRecord == nil {
			return opCreate, client.RRSet{
				Description: "cert-manager",
				TTL:         cfg.EffectiveTTL(),
				TXTRecord:   &client.TXTRecord{Name: subdomain, Values: []string{ch.Key}},
			}
		}
		values := append([]string{}, existing.RRSet.TXTRecord.Values...)
		values = append(values, ch.Key)
		return opReplace, client.RRSet{
			TTL:       cfg.EffectiveTTL(),
			TXTRecord: &client.TXTRecord{Name: subdomain, Values: values},
		}
	}

	return s.reconcile(ctx, cl, cfg, zone, subdomain, satisfied, mutate)
}
```

- [ ] **Step 4: Run the Present tests to verify they pass**

Run: `go test ./f5xc/ -run 'TestSolver_Present' -v`
Expected: PASS (NewRecord, AppendToExisting, DuplicateValue, ReadBackRecoversLostWrite, ErrorsWhenNeverConverges).

Note: `TestSolver_Present_CertAuth` (still present, closure-based) will now fail because its closure GET does not reflect the create. Fix it in the next step.

- [ ] **Step 5: Repoint TestSolver_Present_CertAuth onto the fake**

In `f5xc/solver_test.go`, REPLACE `TestSolver_Present_CertAuth` with:

```go
func TestSolver_Present_CertAuth(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	s := &Solver{
		clientFactory: func(cfg *F5XCConfig, auth client.Authenticator) (RRSetClient, error) {
			if _, ok := auth.(*client.TokenAuth); ok {
				t.Error("expected CertAuth, got TokenAuth")
			}
			return fc, nil
		},
		secretReader: &fakeSecretReader{data: map[string][]byte{
			"cert.p12": generateTestP12Bytes(t),
			"password": []byte("test-password"),
		}},
	}
	ch := challengeRequest("_acme-challenge.example.com.", "example.com.", "challenge-key", map[string]any{
		"tenantName": "my-tenant", "groupName": "cert-manager",
		"certificateSecretRef": map[string]string{"name": "secret", "p12Key": "cert.p12", "passwordKey": "password"},
	})
	if err := s.Present(ch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := fc.values("_acme-challenge"); len(got) != 1 || got[0] != "challenge-key" {
		t.Fatalf("values = %v, want [challenge-key]", got)
	}
}
```

- [ ] **Step 6: Run the full package tests**

Run: `go test ./f5xc/ -run 'TestSolver_Present' -v`
Expected: PASS including CertAuth.

- [ ] **Step 7: Commit**

```bash
git add f5xc/solver.go f5xc/solver_test.go
git commit -m "feat: serialize and read-back-verify Present via reconcile loop"
```

---

## Task 4: CleanUp

**Files:**
- Modify: `f5xc/solver.go` (rewrite `CleanUp`)
- Modify: `f5xc/solver_test.go` (repoint CleanUp tests onto the fake; add read-back test)

- [ ] **Step 1: Write the failing CleanUp tests (on the fake)**

In `f5xc/solver_test.go`, REPLACE `TestSolver_CleanUp_RemovesOnlyOwnValue`, `TestSolver_CleanUp_ThreeChallenges_RemovesOnlyVerified`, `TestSolver_CleanUp_DeletesWhenLast`, `TestSolver_CleanUp_AlreadyGone`, and `TestSolver_CleanUp_DeleteNotFound` with these fake-backed versions:

```go
func TestSolver_CleanUp_RemovesOnlyOwnValue(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	fc.records["_acme-challenge"] = client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"other-key", "challenge-key"}}}
	if err := fakeSolver(fc).CleanUp(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := fc.values("_acme-challenge")
	if len(got) != 1 || got[0] != "other-key" {
		t.Fatalf("values = %v, want [other-key]", got)
	}
	if fc.deletes != 0 {
		t.Errorf("deletes = %d, want 0 (other value remains)", fc.deletes)
	}
}

func TestSolver_CleanUp_ThreeChallenges_RemovesOnlyVerified(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	fc.records["_acme-challenge"] = client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"key-1", "key-verified", "key-3"}}}
	if err := fakeSolver(fc).CleanUp(f5xcChallenge("key-verified")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := fc.values("_acme-challenge")
	remaining := map[string]bool{}
	for _, v := range got {
		remaining[v] = true
	}
	if len(got) != 2 || !remaining["key-1"] || !remaining["key-3"] {
		t.Errorf("values = %v, want [key-1 key-3]", got)
	}
	if fc.deletes != 0 {
		t.Errorf("deletes = %d, want 0", fc.deletes)
	}
}

func TestSolver_CleanUp_DeletesWhenLast(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	fc.records["_acme-challenge"] = client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"challenge-key"}}}
	if err := fakeSolver(fc).CleanUp(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := fc.values("_acme-challenge"); got != nil {
		t.Fatalf("expected record deleted, values = %v", got)
	}
	if fc.deletes != 1 {
		t.Errorf("deletes = %d, want 1", fc.deletes)
	}
}

func TestSolver_CleanUp_AlreadyGone(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient() // empty
	if err := fakeSolver(fc).CleanUp(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("expected nil error when record absent, got: %v", err)
	}
	if fc.deletes != 0 || fc.replaces != 0 {
		t.Errorf("no write expected; deletes=%d replaces=%d", fc.deletes, fc.replaces)
	}
}

// First delete is silently lost; the read-back must re-issue it and converge.
func TestSolver_CleanUp_ReadBackRecoversLostDelete(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	fc.records["_acme-challenge"] = client.RRSet{TXTRecord: &client.TXTRecord{Name: "_acme-challenge", Values: []string{"challenge-key"}}}
	fc.loseWrites = 1 // drop the first delete
	if err := fakeSolver(fc).CleanUp(f5xcChallenge("challenge-key")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := fc.values("_acme-challenge"); got != nil {
		t.Fatalf("delete did not converge; values = %v", got)
	}
	if fc.deletes < 2 {
		t.Errorf("expected at least 2 delete attempts (one lost), got %d", fc.deletes)
	}
}
```

- [ ] **Step 2: Run the CleanUp tests to verify they fail**

Run: `go test ./f5xc/ -run 'TestSolver_CleanUp' -v`
Expected: FAIL — `CleanUp` still uses the old direct flow; read-back recovery and exact counts fail.

- [ ] **Step 3: Rewrite CleanUp**

In `f5xc/solver.go`, replace the whole existing `CleanUp` func with:

```go
// CleanUp removes this challenge's value from the TXT record, preserving any other
// values (concurrent challenges for the same FQDN), deleting the record only when no
// values remain. Idempotent and safe under concurrency.
func (s *Solver) CleanUp(ch *acme.ChallengeRequest) error {
	cfg, cl, err := s.setup(ch)
	if err != nil {
		return err
	}

	ctx := context.Background()
	zone := unFQDN(ch.ResolvedZone)
	subdomain := extractSubDomain(ch.ResolvedFQDN, ch.ResolvedZone)

	klog.V(2).InfoS("f5xc: cleaning up challenge", "fqdn", ch.ResolvedFQDN, "zone", zone, "subdomain", subdomain)

	satisfied := func(values []string) bool {
		return !containsValue(values, ch.Key)
	}
	mutate := func(existing *client.APIRRSet) (rrsetOp, client.RRSet) {
		// Reached only when existing contains ch.Key (otherwise satisfied is true).
		remaining := make([]string, 0, len(existing.RRSet.TXTRecord.Values))
		for _, v := range existing.RRSet.TXTRecord.Values {
			if v != ch.Key {
				remaining = append(remaining, v)
			}
		}
		if len(remaining) == 0 {
			return opDelete, client.RRSet{}
		}
		return opReplace, client.RRSet{
			TTL:       cfg.EffectiveTTL(),
			TXTRecord: &client.TXTRecord{Name: subdomain, Values: remaining},
		}
	}

	return s.reconcile(ctx, cl, cfg, zone, subdomain, satisfied, mutate)
}
```

- [ ] **Step 4: Run the CleanUp tests to verify they pass**

Run: `go test ./f5xc/ -run 'TestSolver_CleanUp' -v`
Expected: PASS (all five).

- [ ] **Step 5: Remove the now-unused closure mock**

After Tasks 3–4, the original closure-based `mockClient` (struct + its `GetRRSet`/`CreateRRSet`/`ReplaceRRSet`/`DeleteRRSet` methods) and the `tokenSolver` helper are no longer referenced by any test. Go compiles fine with unused package-level decls, but golangci-lint's `unused` linter (U1000) fails CI on them. Delete from `f5xc/solver_test.go`:
- the `mockClient` struct definition and its four methods
- the `tokenSolver` func

Keep `challengeRequest`, `f5xcChallenge`, `fakeSecretReader`, and `generateTestP12Bytes` — they are still used.

- [ ] **Step 6: Run the whole f5xc package and the unused linter**

Run:
```bash
go test ./f5xc/ -v
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2 run ./...
```
Expected: tests PASS; golangci-lint reports `0 issues` (no `U1000` for `mockClient`/`tokenSolver`). If U1000 still fires, a leftover reference or decl remains — remove it.

- [ ] **Step 7: Commit**

```bash
git add f5xc/solver.go f5xc/solver_test.go
git commit -m "feat: serialize and read-back-verify CleanUp via reconcile loop"
```

---

## Task 5: Headline lost-update concurrency test

**Files:**
- Modify: `f5xc/solver_test.go` (add concurrent Present test)

- [ ] **Step 1: Write the concurrency test**

Append to `f5xc/solver_test.go`:

```go
// With many concurrent Present calls for distinct keys on the SAME FQDN, all values
// must survive. The per-FQDN lock serializes the read-modify-write; without it the
// GET→REPLACE cycles interleave and lose updates. Run under -race.
func TestSolver_Present_ConcurrentSameFQDN_NoLostUpdates(t *testing.T) {
	fastReconcile(t)
	fc := newFakeRRSetClient()
	s := fakeSolver(fc)

	const n = 25
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("key-%02d", i)
		go func() {
			defer wg.Done()
			if err := s.Present(f5xcChallenge(key)); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Present error: %v", err)
	}

	got := fc.values("_acme-challenge")
	if len(got) != n {
		t.Fatalf("got %d values, want %d (lost updates): %v", len(got), n, got)
	}
	seen := map[string]bool{}
	for _, v := range got {
		seen[v] = true
	}
	for i := 0; i < n; i++ {
		if key := fmt.Sprintf("key-%02d", i); !seen[key] {
			t.Errorf("missing value %q", key)
		}
	}
}
```

Note: `solver_test.go` must import `fmt` (add it if not already imported).

- [ ] **Step 2: Run the test under the race detector to verify it passes**

Run: `go test -race ./f5xc/ -run TestSolver_Present_ConcurrentSameFQDN_NoLostUpdates -v`
Expected: PASS, no race warnings. (Sanity check that it is meaningful: temporarily commenting out `s.locks.Lock(key)`/`Unlock` in `reconcile` makes this fail with fewer than 25 values — do not commit that change.)

- [ ] **Step 3: Commit**

```bash
git add f5xc/solver_test.go
git commit -m "test: prove per-FQDN lock prevents concurrent lost updates"
```

---

## Task 6: Live concurrent integration scenario (gitignored)

**Files:**
- Modify: `f5xc/integration_p12_test.go` (build tag `integration`, gitignored)

- [ ] **Step 1: Add the concurrent live scenario**

Append to `f5xc/integration_p12_test.go`:

```go
// TestIntegration_P12_ConcurrentPresent fires many Present calls for distinct keys
// on the SAME FQDN simultaneously against the real F5 XC API, then verifies all of
// them survived (today's un-serialized code loses values here). It then cleans each
// up one by one and asserts convergence.
func TestIntegration_P12_ConcurrentPresent(t *testing.T) {
	env := loadITEnv(t)
	s := newITSolver(env)
	vc := verifyClient(t, env)

	fqdn := env.fqdn("concurrent")
	requireEmpty(t, vc, env, fqdn)

	const n = 5
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("it-concurrent-%d", i)
	}
	t.Cleanup(func() {
		for _, k := range keys {
			_ = s.CleanUp(itChallenge(env, fqdn, k))
		}
	})

	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	for _, k := range keys {
		k := k
		go func() {
			defer wg.Done()
			if err := s.Present(itChallenge(env, fqdn, k)); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Present error: %v", err)
	}

	vals := currentValues(t, vc, env, fqdn)
	for _, k := range keys {
		if !contains(vals, k) {
			t.Fatalf("value %q lost under concurrency; have %v", k, vals)
		}
	}

	// Clean up one at a time; each removal keeps the others until its turn.
	for i, k := range keys {
		if err := s.CleanUp(itChallenge(env, fqdn, k)); err != nil {
			t.Fatalf("CleanUp %s: %v", k, err)
		}
		for _, other := range keys[i+1:] {
			if !contains(currentValues(t, vc, env, fqdn), other) {
				t.Fatalf("%s wrongly removed while cleaning %s", other, k)
			}
		}
	}
	if vals := currentValues(t, vc, env, fqdn); len(vals) != 0 {
		t.Fatalf("expected empty at end; have %v", vals)
	}
}
```

Also extend the reset label list in `TestIntegration_P12_Reset` to include `"concurrent"`:

```go
	for _, label := range []string{"single", "idem", "shared", "absent", "cert1", "cert2", "cert3", "cert4", "concurrent"} {
```

Note: `integration_p12_test.go` already imports `fmt` and `sync` is needed — add `"sync"` to its import block.

- [ ] **Step 2: Compile-check under the integration build tag**

Run: `go vet -tags integration ./f5xc/`
Expected: no output (compiles).

- [ ] **Step 3: Run the live scenario (requires credentials)**

Run:
```bash
set -a; . ./.f5xc-it.env; set +a
export F5XC_IT_P12_FILE="$(pwd)/$(grep -oE '[^=]+\.p12' .f5xc-it.env | head -1 || echo f5-cz.console.ves.volterra.io.api-creds.p12)"
go test -tags integration -v -timeout 300s ./f5xc/ -run TestIntegration_P12_ConcurrentPresent
```
Expected: PASS — all 5 values present after concurrent Present, clean convergence after cleanups. (If skipped due to missing `F5XC_IT_*`, set them per `docs`/memory and re-run.)

- [ ] **Step 4: No commit**

This file is gitignored. Nothing to commit; the change stays local.

---

## Task 7: Final verification + CHANGELOG

**Files:**
- Modify: `CHANGELOG.md` (Unreleased entry)

- [ ] **Step 1: Run the full local verification suite**

Run:
```bash
go test ./... 
go test -race ./f5xc/
go vet ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2 run ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2 run --build-tags integration ./...
```
Expected: all pass, golangci-lint reports `0 issues` for BOTH build-tag variants (this catches the cross-build-tag typecheck class of failure that `go vet` misses).

- [ ] **Step 2: Add a CHANGELOG entry under Unreleased**

In `CHANGELOG.md`, add directly under the top header block (above the latest released version):

```markdown
## [Unreleased]

### Fixed

- Concurrent challenges for the same FQDN (apex + wildcard SANs, or many certificates issued at once) no longer lose TXT values. `Present`/`CleanUp` now serialize the read-modify-write of each shared RRSet with a per-FQDN lock and verify the result with a post-write read-back, re-applying idempotently if a write did not land.
```

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: changelog for concurrent RRSet safety"
```

- [ ] **Step 4: Release (user-driven, not part of this plan)**

Cutting a release (version bump + tag) is done by the user. When asked, follow the version-bump checklist (Chart.yaml version/appVersion/image/artifacthub, both READMEs, CHANGELOG move from Unreleased to the version, compare link) and push a `vX.Y.Z` tag. A new concurrency-safety feature is a minor bump (e.g. 0.5.0) under semver, but the user decides the number. Verify CI is green before tagging.

---

## Self-Review Notes

- **Spec coverage:** keyed mutex (Task 1), unified reconcile loop + Present/CleanUp via satisfied/mutate (Tasks 3–4), error handling + bounded read-back + not-found (Task 3 reconcile + tests), eventual-consistency tolerance via re-apply (Tasks 3–4 read-back tests), constants `verifyAttempts`/`verifyInterval` (Task 2), stateful fake + repointed tests (Tasks 2–4), headline lost-update test (Task 5), live concurrent scenario (Task 6). All spec sections map to a task.
- **No placeholders:** every code and command step is concrete.
- **Type consistency:** `reconcile(ctx, cl, cfg, zone, subdomain, satisfied, mutate)`, `rrsetOp{opCreate,opReplace,opDelete}`, helpers `lockKey`/`currentValues`/`containsValue`, `keyedMutex.Lock/Unlock/len`, fake methods matching the `RRSetClient` interface signatures, and `verifyAttempts`/`verifyInterval` are used identically across tasks.
