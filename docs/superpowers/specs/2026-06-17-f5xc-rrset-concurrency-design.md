# F5 XC RRSet concurrency — design

**Date:** 2026-06-17
**Status:** Approved design, pending implementation plan
**Component:** `f5xc/solver.go` (+ small new helper); `f5xc/client/` unchanged

## Problem

`Present` and `CleanUp` mutate a shared TXT RRSet with a non-atomic read-modify-write:
GET the current values → modify in memory → REPLACE (or CREATE/DELETE). When several
challenges target the **same** `_acme-challenge.<name>` RRSet — apex + wildcard SANs,
or overlapping orders — concurrent operations can lose updates:

```
challenge B: GET -> [A]
challenge C: GET -> [A]          (before B writes)
B: REPLACE [A, B]
C: REPLACE [A, C]                -> B is lost
```

The F5 XC `dns_zone/rrset` API offers **only Create/Get/Replace/Delete** — no atomic
add/remove of a single value, and **no optimistic concurrency** (no `resource_version`,
ETag, or `If-Match`). So a correct concurrent mutation cannot be expressed as a single
API call, and a compare-and-swap retry is not available at the protocol level. Error
code 14 ("Previous DNS zone change is pending") serializes *writes* but does not make
read-modify-write atomic.

## Constraints & context

- The webhook runs as a **single replica** (confirmed). Races are therefore intra-process,
  between concurrent goroutines in the webhook apiserver handling concurrent
  `Present`/`CleanUp` calls.
- `Present` and `CleanUp` are already idempotent (v0.4.0): `Present` skips a value that is
  already present; `CleanUp` removes only its own value and treats not-found as success.
- The client already retries transient code 14 on Create/Replace/Delete (`doWithRetry`).

## Chosen approach: per-FQDN lock + post-write read-back verification

Two layers, both in the solver:

1. **Per-FQDN in-process lock** serializes the read-modify-write for a given RRSet,
   deterministically eliminating the intra-process race (the real, common cause at one
   replica).
2. **Post-write read-back verification with bounded reconcile** confirms the write actually
   landed (durability / eventual-consistency check) and repairs it if not — and keeps the
   solution forward-safe if ever scaled past one replica.

The client (`f5xc/client/`) stays a thin API wrapper; all serialization and reconcile
*policy* lives in the solver, which knows the desired end-state.

## Architecture

### Keyed mutex

A small refcounted keyed-mutex helper, owned by `Solver` (created in `NewSolver`).

- Key = RRSet identity: `zone/group/subdomain/TXT`.
- `Lock(key)` / `Unlock(key)`; entries are refcounted and removed when the last holder
  releases, so the map does not leak across many distinct FQDNs.
- Distinct FQDNs never block each other — issuing certs for **different** domains stays
  fully parallel (the four-certs case is unaffected).

### Unified reconcile loop

`Present` and `CleanUp` collapse into one loop parameterized by two functions, both
receiving the current RRSet from the GET (`nil` when the record is absent):

- `satisfied(current) bool` — is the desired state already true? (reads the current values)
  - Present: `key ∈ values`
  - CleanUp: `key ∉ values`
- `mutate(current) operation` — how to reach it (uses presence/absence to choose the op):
  - Present: append `key` → REPLACE, or CREATE `[key]` if the RRSet is absent
  - CleanUp: drop `key` → REPLACE remaining, or DELETE if none remain

```
lock(key); defer unlock(key)
for attempt := 1..verifyAttempts:
    cur := GET(rrset)                  // tolerate not-found per operation
    if satisfied(cur):                 // this GET is the read-back verification
        return nil
    apply(mutate(cur))                 // CREATE / REPLACE / DELETE (idempotent)
    sleep(verifyInterval)              // let read-after-write propagate
return error("value not converged after N attempts")
```

The read-back is structural: the first iteration applies the change; the next iteration's
GET re-checks `satisfied`. No contention → converges in 2 GETs + 1 write (one extra GET
versus today, no redundant write). Loss/lag → re-apply (safe, idempotent) up to the bound.

## Error handling & eventual consistency

- **Bounds (package `var`, overridable in tests like the existing retry vars):**
  `verifyAttempts = 3`, `verifyInterval = 500ms`.
- **Writes:** transient code 14 already retried by the client's `doWithRetry`; unchanged.
- **GET inside the loop:** not-found (HTTP 404 / API code 5) via `client.IsNotFound` →
  for CleanUp this is `satisfied` (done); for Present it means CREATE. Other errors
  (auth, non-14 5xx) → fail fast and return.
- **Lag vs. genuine loss:** under the lock the only ways a read-back fails are propagation
  delay or a real F5 XC drop. The reaction is identical — wait `verifyInterval` and re-apply
  idempotently — so no distinction is needed. Lag resolves by waiting; a drop is repaired.
- **Exhaustion:** after `verifyAttempts` still unsatisfied → return an error
  (`f5xc: value not converged ...`, logged at warning with details). cert-manager retries the
  whole challenge, which is safe because every operation is idempotent.
- **Lock hold time:** the lock is held for the whole loop, including backoff sleeps. It is
  per-FQDN, so other domains are unaffected; same-FQDN operations must serialize anyway.
  Bounded at roughly `verifyAttempts × verifyInterval` (~1.5 s worst case) plus API time.

## Testing

### Unit

1. **keyedMutex** — mutual exclusion per key, independence across keys, no map leak
   (refcount returns to zero), concurrent goroutines.
2. **Stateful fake client** — a small in-memory fake where GET reflects prior
   CREATE/REPLACE/DELETE, so the read-back loop sees its own writes. The existing
   closure-based `mockClient` is kept for error/lag injection.
3. **Present via loop** — create-new, append-to-existing, duplicate (no write, satisfied
   immediately), read-back retry (first post-write GET missing → re-apply → second present →
   converges), exhaustion (never lands → error after N).
4. **CleanUp via loop** — remove own value (others kept), last value → delete, not-found →
   satisfied without error, read-back retry.
5. **Lost-update prevention (headline)** — `K` goroutines call `Present` with distinct keys
   on the **same** FQDN against the stateful fake with a simulated race window (sleep between
   GET and REPLACE). With the lock, all `K` values are present at the end.
6. **Existing `TestSolver_*`** — repointed onto the stateful fake, since they now traverse
   the read-back path.

### Live integration (gitignored `f5xc/integration_p12_test.go`)

7. **Concurrent Present against real F5 XC** — `K` goroutines, distinct keys, same FQDN,
   fired simultaneously; then GET and assert all `K` values present (today's code loses here).
   Then sequential CleanUp, assert convergence. Self-cleaning + reset, consistent with the
   existing harness.

## Out of scope (YAGNI)

- Cross-replica coordination beyond what read-back provides (single replica today).
- Exposing `verifyAttempts` / `verifyInterval` via Helm/solver config (internal constants
  for now).
- Any client-level API change (no CAS available; nothing to add).
