# Call-stack Heap: Attribution & Trim — Design

**Date:** 2026-07-06
**Status:** Approved (brainstorming) — ready for `writing-plans`
**Scope:** `engine` + Java language support + perf harness/docs. Heap track of the performance backlog.

## Summary

The AST-detach work (`feat/callstack-ast-detach`) removed the dominant heap term on large
scans — whole-file AST pinning by the call-stack (the measured ~7 GB on Keycloak). A smaller
residual remains: the post-GC heap floor still grows over a scan (observed ~1.6 → ~3.4 GB).
That growth was *hypothesized* to be `JavaAggregator.detectedNodes`, but it was never
attributed, and the now-uncapped detached call-stack population is an equally plausible
source.

This design does two things, in order:

1. **H1 — Attribute the floor (the gate).** Measure what actually grows the post-detach
   floor, split across three buckets: retained CBOM `INode`s, detached call-stack records,
   and hooks. The result decides how much of H2 to build and whether `detectedNodes` earns
   its own future spec.
2. **H2 — Trim the call-stack.** Land the *deferred* Phase-1 work from
   `docs/superpowers/plans/2026-07-05-callstack-hooks-heap-reduction.md`: an eligibility
   filter that stops recording library calls (Tasks 1–2, done regardless), and — **only if
   H1 shows the detached population is still material** — a retention cap (Task 5).

Measure first, so we don't trim a term that no longer dominates.

## Background / Why now

The original heap plan phased the work as: Phase 1 (trim + bound what enters the call-stack)
→ Phase 2 (detach recorded calls from the AST). In practice **Phase 2 shipped first** and
some of Phase 1 shipped alongside it:

| Original Phase-1 task | Status |
|---|---|
| Task 3 — drop redundant `visitedTreeObjects` | **Done** |
| Task 4 — key-indexed subscription lookup | **Done** |
| Task 1–2 — `isHookEligibleCall` filter (skip library calls) | **Not done** |
| Task 5 — retention caps / overflow WARN | **Not done** |
| Phase 2 — AST detach | **Done** (out of order) |

Because detach landed, the old Task-6 measurement (pre-detach, ~7 GB, AST-pinning-dominated)
no longer describes the current heap. H1 re-measures the *post-detach* residual; H2 finishes
the deferred trim.

### Load-bearing facts (verified in the original plan, still hold post-detach)

- The call-stack (`CallStackAgent.invokedCallStack`) is project-lifetime: one record per
  distinct recorded invocation, released only by the end-of-scan `ScannerManager.reset()`.
  Measured growth is **linear and unbounded** in project size (~179k records at ~63M calls
  on Keycloak). Detach shrank each record's footprint (no AST pin) but **not the count**.
- Method hooks are created only from **user methods with a source declaration**
  (`JavaDetectionEngine`, `declaration() != null`). A hook's matcher encodes a **specific
  user-class FQN** and matches only `invokedObjectType.is(userClassFQN) AND name AND params`.
  ⇒ A recorded **library** call (library owner type, no source declaration) can never match
  any method hook. Recording it is pure waste. **Enum** accesses match a separate `EnumHook`
  path and must stay recorded.
- Cross-file resolution replays the *entire accumulated* call-stack (a hook created in file B
  resolves a call in file A), so retention **cannot** be scoped per file. This is why the
  trim is an eligibility filter (never record the useless calls) rather than per-file
  clearing.

## H1 — Attribute the floor

**Problem.** The perf harness (`CallStackHeapPerfTest`) prints `heapDeltaMB` and
`CallContextStats` (retained-with-tree vs. detached counts), but nothing attributes retained
*bytes* to a source. We can't currently tell call-stack from `detectedNodes` from hooks.

**Approach — two signals:**

1. **In-process object counts (cheap, always-on).** Extend the end-of-scan reporting to emit,
   alongside `CallContextStats`:
   - `JavaAggregator.getDetectedNodes().size()` (retained CBOM node count),
   - detached call-stack record count (already in `CallContextStats.detached()`),
   - hook-subscription counts (`HookRepository` / `HookDetectionObservable`).

   Surface these in two places: the `CallStackHeapPerfTest` report line, and a single DEBUG
   log at end-of-scan (in `ScannerManager` or the aggregator) so they appear on a real
   Keycloak run too. These are counts, not bytes — they size *populations*, not footprint.

2. **True byte attribution (manual, decisive).** On a constrained-heap Keycloak scan using the
   existing `jmap -histo:live` protocol in `docs/PERFORMANCE_TESTING.md`, attribute retained
   bytes across three buckets:
   - CBOM model: `com.ibm.mapper.model.*` `INode` subclasses (Algorithm, Key, Property, …),
   - Call-stack: `DetachedCall`, `ArgSnapshot`, `ResolvedSnapshotValue`,
   - Residual `Tree`/hooks: any `org.sonar.*` Tree still retained + hook structures.

**Deliverable.** A short attribution table appended to `docs/PERFORMANCE_TESTING.md` (or a
dated note) plus a one-paragraph **decision**:
- Residual floor is **call-stack-dominated** → build H2's cap (Task 5) as well as the filter.
- Residual floor is **`detectedNodes`-dominated** → build only H2's filter (still a lossless
  trim + CPU assist); open a *separate* spec for `detectedNodes` (dedup / incremental
  emission). That spec is explicitly **out of scope here**.
- Residual floor is **hooks-dominated** → open a hooks-pruning spec (was Tier-3 item H3).

H1 has no acceptance test beyond "the numbers are captured and the decision is written."

## H2 — Trim the call-stack

### Eligibility filter (Tasks 1–2) — build regardless of H1

Add a language-layer predicate that mirrors the existing `isDetachableCall` sibling:

- **`engine/.../language/ILanguageSupport.java` (or `ILanguageTranslation`)** — add
  `default boolean isHookEligibleCall(T tree) { return true; }`. Keeping it a defaulted method
  leaves Python/Go on record-all (unchanged behavior).
- **`engine/.../language/java/JavaLanguageSupport.java`** — implement for Java: `true` for
  enum accesses (must stay recorded for `EnumHook`) and for calls whose invoked-object owner
  type *could* be a user class; `false` for library calls. **Predicate premise correction:**
  the discriminator is **not** `methodSymbol().declaration() != null` — cross-file *user* calls
  resolve their callee via `sonar.java.binaries` and have a null declaration too (see the
  comment in `JavaLanguageSupport.isDetachableCall`, `:165-172`), so that predicate would drop
  exactly the cross-file detections we must keep. There may be no clean intrinsic AST/symbol
  signal separating a binary-resolved user class from a library class; the real discriminator
  must be **pinned empirically** against the `crossfile/` fixtures (a characterization test)
  before the filter body is written, and may end up coarser (e.g. a library-package check).
  DEBUG-log skips.
- **`engine/.../language/java/JavaDetectionEngine.java`** — gate at the **top of
  `recordCall` (`:135`)**, i.e. *before* `isDetachableCall`/`buildDetachedCall`. Returning
  early for library calls means they are neither recorded **nor** put through the expensive
  translate + argument-snapshot in `buildDetachedCall` — a free assist to the C2 throughput
  finding (that snapshot currently runs per root-rule per invocation).

**Losslessness.** A library call cannot match any method hook (matcher requires a specific
user-class owner). The single bounded edge — a user class that *overrides* a library method
and is hooked via that override — is documented and DEBUG-logged. Everything else is a strict
no-op change to detections.

### Retention cap (Task 5) — build only if H1 says so

If H1 shows the detached population is a material heap term:
- Per-name-bucket cap **and** a global `invokedCallStack` cap, with sensible defaults,
  overridable via a plugin property.
- On overflow, stop recording new calls for that bucket and emit a **single** WARN naming the
  method + cap, so the (bounded, measurable) detection loss is explicit.

If H1 shows the call-stack is *not* a material term post-detach, defer the cap with a written
note (the filter alone suffices, and adds no loss).

## Components & data flow

```
recordCall (JavaDetectionEngine:135)
  └─ isHookEligibleCall(invocation)?          ← NEW gate (Task 1–2)
        false → return (skip record + skip buildDetachedCall)   [library call]
        true  → isDetachableCall? → buildDetachedCall (unchanged)
                 addRecordedCall → CallStackAgent.add
                                     └─ (optional) cap check      ← NEW (Task 5, conditional)
```

Reporting/attribution (H1) reads existing accessors: `callContextStats()`,
`JavaAggregator.getDetectedNodes()`, hook repositories — no data-flow changes, read-only.

## Testing

- **Cross-file regression guard (reuse existing).** `CrossFileHookDetachTest` and
  `IsDetachableCallTest` already exercise cross-file hook resolution and the
  detach-eligibility predicate. Add a sibling assertion (or a focused test) proving a
  cross-file detection whose call site is a **user** method still resolves *with the filter
  on*, and that a purely-library call is correctly skipped. This is the guard CI otherwise
  lacks (all rule tests are single-file).
- **Filter unit coverage.** Table-style test of `isHookEligibleCall` on: library invocation
  (false), user-declared invocation (true), enum access (true), the override edge (true,
  documented).
- **Regression.** `mvn test -pl engine` and `mvn test -pl java` stay green.
- **Perf validation.** Re-run `CallStackHeapPerfTest` (`-Dtest=CallStackHeapPerfTest
  -DexcludedGroups=`) and confirm detached counts drop by the library-call fraction; re-run
  the Keycloak `jmap` attribution from H1 and record the floor delta.

## Constraints

- Java 17; changes confined to `engine` + Java language support + `java` test/perf + docs.
- Apache 2.0 header in every new `.java` file. `mvn spotless:apply` before commit (restore
  `JsonCipherSuites` if Spotless truncates it — known issue).
- Keep the generic engine language-agnostic: eligibility goes through the language layer, not
  into generic engine code. Python/Go remain on the `true` default.

## Out of scope

- `JavaAggregator.detectedNodes` dedup / incremental CBOM emission — H1 only decides whether
  it earns its own spec.
- C1 root pre-filtering and the other CPU/throughput items — separate "throughput track" spec.
- Hooks-subscription pruning (H3) — only opened if H1 finds hooks material.

## Sequencing

1. H1 in-process counts + one-shot Keycloak `jmap` attribution → write the decision.
2. H2 eligibility filter (Tasks 1–2) + cross-file/unit tests.
3. H2 cap (Task 5) **iff** H1 said call-stack is material.
4. Re-measure; record the floor delta.
