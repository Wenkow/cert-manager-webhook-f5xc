# F5 XC RRSet concurrency — design

**Date:** 2026-06-17
**Status:** Approved design, validated by live measurement 2026-09-24; pending implementation
**Revised:** 2026-09-24 — measurements added, verify bounds retuned
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

## Measurements (live tenant, 2026-09-24)

Taken with a throwaway probe in package `client` (`integration_zonelock_test.go`,
gitignored) against tenant `f5-cz`, zones `xyapps.dev` and `xc.f5playground.xyz`.
It ran with the client's own code-14 retry disabled, so it observed raw 503s.

| Question | Result |
|---|---|
| Is serialisation per RRSet or per zone? | **Per zone** — 3 of 3 writes to a *different* RRSet issued right after a committed write got code 14. |
| Do different zones block each other? | **No** — 0 of 5. Serialisation is per zone, not per tenant. |
| Zone settle time T | median **1.32 s**, min 1.29 s, **max 3.22 s** |
| 10 concurrent writes, distinct RRSets, one zone | **10 of 10 succeeded**, slowest 590 ms, zero code 14 |
| Two concurrent `Present` on one shared RRSet | **Value lost on the first attempt** |
| Five concurrent `Present` on one shared RRSet, no lock (2026-09-24, token auth) | **HTTP 400** `duplicate RR type: 'TXT'` |

Three of these corrected working assumptions, and they are the reason this
revision exists:

1. **Code 14 is not a throughput problem.** Writes that arrive *simultaneously*
   are coalesced into a single pending zone change and all succeed. Code 14
   appears only for a write arriving *after* a change has begun committing — so
   the sequential probe collided every time and the concurrent one never did. A
   10-SAN certificate's `Present` phase finishes in well under a second.
2. **The existing 60 s retry budget is ample.** At T≈1.32 s it covers roughly 45
   serialised writes. An earlier hypothesis that the budget was exhausted at
   12–14 SANs assumed T≈4–5 s and is wrong.
3. **A per-zone lock was considered and rejected.** It was proposed to fix the
   throughput problem that measurement showed does not exist; it would only
   serialise work the API already accepts in parallel. The per-FQDN granularity
   below is correct.

A later run of the five-way scenario against the live API (with the lock removed,
to confirm the test is not vacuous) showed a second failure mode: when several
goroutines see the RRSet as absent at the same moment, they all issue CREATE and
the API rejects the losers with HTTP 400, `Record '...' contains duplicate RR type:
'TXT'`. So an un-serialized read-modify-write does not only lose values silently —
on a record that does not exist yet it fails the challenge outright. The per-FQDN
lock fixes both, since only one goroutine ever decides create-vs-replace.

The remaining, measured failure is the lost update — which is what actually
prevents a multi-SAN certificate (apex + wildcard) from validating.

## Constraints & context

- The webhook runs as a **single replica** (confirmed — `replicas: 1` is hardcoded
  in `deploy/.../templates/deployment.yaml`, not wired to values.yaml, so it cannot
  be scaled out by configuration). Races are therefore intra-process, between
  concurrent goroutines in the webhook apiserver handling concurrent
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
  `verifyAttempts = 5`, `verifyInterval = 1s` — a 5 s read-back budget.

  Retuned 2026-09-24. The original `3 × 500ms` gave 1.5 s, which is below the
  measured median settle time of 1.32 s and well below the observed maximum of
  3.22 s: the read-back would routinely expire before a change had propagated and
  `Present` would fail a challenge that was in fact fine. 5 s clears the measured
  maximum with margin.
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
  Bounded at roughly `verifyAttempts × verifyInterval` (~5 s worst case) plus API time.
  Measurement backs this being acceptable: distinct FQDNs do not contend, and ten of
  them complete in under a second.

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
   fired simultaneously; then GET and assert all `K` values present. Then sequential
   CleanUp, assert convergence. Self-cleaning + reset, consistent with the existing harness.

   The 2026-09-24 probe already demonstrated the *failure* on the live API (one of two
   values dropped on the first attempt), so this test's job is to prove the *fix*: the
   same scenario must now keep every value. Run it before and after wiring the lock.

## Out of scope (YAGNI)

- **A per-zone or tenant-wide write queue.** Measurement shows simultaneous writes are
  coalesced and that zones do not block each other, so neither would fix anything the
  per-FQDN lock does not already cover.
- **Jitter or exponential backoff on the code-14 retry.** Worth considering if the
  staggered `CleanUp` phase ever proves to collide in practice, but the current constant
  2 s / 60 s retry has ~59 s of headroom at the measured settle time. No change now.
- Cross-replica coordination beyond what read-back provides (single replica today).
- Exposing `verifyAttempts` / `verifyInterval` via Helm/solver config (internal constants
  for now).
- Any client-level API change (no CAS available; nothing to add).
