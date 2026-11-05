# Call-Stack Heap/Perf Harness — Design

**Date:** 2026-07-06
**Branch context:** `feat/callstack-ast-detach`
**Status:** Approved (design), pending implementation plan.

## Goal

A single, **manual-on-demand** JUnit test that stresses the `CallStackAgent` call
retention mechanism at scale and **deterministically asserts** that recorded calls get
detached (per-file ASTs released) at `leaveFile` — the observable signature of the
`feat/callstack-ast-detach` fix — while also **reporting** heap and wall-time for manual
inspection.

Constraints, from brainstorming:

- **Self-contained JUnit** — no keycloak checkout, no docker/SonarQube, no network. The
  corpus is generated in-process into a temp dir.
- **Not keycloak** — a synthetic corpus of similar *shape* (cross-file crypto calls), with
  scale as a tunable knob, standing in for a large real project.
- **Types must resolve** — the heap term only appears when detections actually fire. A
  source-only scan resolves nothing → `addCall` fires 0 times → the term is 0 (see
  `docs/superpowers/plans/2026-07-05-callstack-hooks-heap-reduction.md`, "Measured"
  section, and the `callstack-heap-term-measured` project memory). So the harness must
  compile the corpus and put it on the semantic classpath, exactly as
  `CrossFileHookDetachTest` does.
- **Deterministic gate, no heap-threshold flake** — assert on a *structural* invariant
  (how many recorded calls still pin a live AST after the scan), not on measured MB. Heap
  MB is reported only, never asserted.
- **Manual only** — `@Tag("performance")`, excluded from the default build. It does not
  gate CI. It is run explicitly when validating a change.

## Why this shape (context)

The `CallStackAgent` records a `CallContext` per matched invocation for the whole scan so
that a hook created in file B can resolve a call recorded in file A (cross-file detection).
Before the detach work, every retained `CallContext` held a live sonar-java `Tree`, and any
`Tree` pins its whole file's AST (parent chain → `CompilationUnitTree`), so the retained set
pinned effectively the whole project's AST at once — measured at ~179k `CallContext`s /
~7 GB on a near-full keycloak scan, growing linearly and unbounded.

The fix (`feat/callstack-ast-detach`): at `leaveFile`, each retained call that is detachable
is swapped for a tree-free `DetachedCall` (`CallStackAgent.detachCallsForFile`), so the
file's AST becomes GC-eligible while cross-file matching continues from an AST-free snapshot.

This harness proves that mechanism works at scale without needing the full keycloak route.
It does **not** try to reproduce the literal 7 GB number; that remains the documented manual
`mvn sonar:sonar` measurement (pointer kept in the test's javadoc).

## Components

### 1. `CryptoCorpusGenerator` (test helper)

Programmatically writes `N` `.java` source files into a temp dir. It emits the exact pattern
the retention mechanism keys on — a cross-file wrapper/caller shape mirroring the
`CrossFileHookDetachTest` fixtures (`KeyGeneratorWrapper` / `KeyGeneratorCaller`) — not flat
single-file crypto calls, because:

- Cross-file wrapper calls are what create **method hooks** (user method with a source
  declaration) and cause calls to be **recorded and later replayed** — the code path that
  accumulates `CallContext`s.
- **Distinct** class/method names per unit keep call sites distinct so retention grows with
  corpus size (a flat corpus with one repeated call site would dedup to ~nothing and not
  stress the term).

Per generated "unit" (parameterized, repeated `N` times with unique names):

- A **wrapper** class exposing a crypto factory method that internally calls a resolvable JCA
  API (`Cipher.getInstance` / `KeyGenerator.getInstance` / `MessageDigest.getInstance`,
  rotated across units so multiple rules fire).
- A **caller** class that invokes the wrapper across the file boundary with:
  - a **string literal** argument (→ detachable),
  - a **field-constant** argument (→ detachable),
  - a **`new byte[]`** argument (→ retained; stays on the tree path by design — this is the
    known non-detachable case).

Scale knob: `-Dperf.corpus.files` (integer, default small — see Open Parameters). "Files"
counts source files; each unit is 2 files (wrapper + caller), so units = files / 2.

The generator returns the list of generated file paths (for `onFiles`) so the test does not
hard-code fixture names.

### 2. Driver (the test)

`CallStackHeapPerfTest extends TestBase`, `@Tag("performance")`. Reuses
`CrossFileHookDetachTest`'s proven driving path verbatim, at scale:

1. Generate the corpus (component 1) into a temp dir.
2. Compile all generated sources to a classpath output dir via
   `ToolProvider.getSystemJavaCompiler` (same helper shape as
   `CrossFileHookDetachTest.compileToClasspath`).
3. `CheckVerifier.newVerifier().onFiles(allGeneratedFiles).withClassPath(List.of(classes))
   .withChecks(this).verifyIssues()` — compiling + classpath is what makes the callee types
   resolve at the call sites so cross-file detections fire and `addCall` runs.

`verifyIssues()` is used (not a bare scan) to stay on the exact, supported CheckVerifier code
path the rest of the suite uses; the harness does not assert specific issue lines (the
corpus is generated, so issue positions are not hand-authored). The perf assertions come
from the call-context stats, not from CheckVerifier issue matching.

### 3. Inspection accessor (small production addition)

`CallStackAgent.invokedCallStack` is `private` with no accessor. Add a minimal read-only
introspection method rather than using reflection (clearer, and legitimate test-support
surface):

- `CallStackAgent`: add a `CallContextStats callContextStats()` that walks
  `invokedCallStack` once and returns counts:
  - `retainedWithTree` — `RetainedCall` entries whose `tree() != null` (i.e. still pinning an
    AST),
  - `detached` — `DetachedCall` entries,
  - `total`, `buckets`.
- `CallContextStats` — a small immutable value type (record) in
  `com.ibm.engine.callstack`.
- Thread the accessor out so the test can reach it after the scan:
  `CallStackAgent.callContextStats()` → `Handler.callContextStats()` →
  `ILanguageSupport` (a `callContextStats()` method) → reachable from the test via
  `JavaAggregator.getLanguageSupport()`.

This is production code but purely additive and read-only; it computes on demand and retains
nothing.

### 4. Metrics + report

After the scan completes (all files have been left, so detach has run for every file):

**ASSERT — deterministic gate (the point of the test):**

- `retainedWithTree <= bound`, where `bound` accounts only for the intentionally-retained
  `new byte[]` cases plus any non-detachable calls (i.e. roughly proportional to units, not
  to total recorded calls). The precise bound formula is derived during implementation from
  the generator's known unit count and validated empirically (see "Validating the harness").
- `detachedRatio = detached / (detached + retainedWithTree) >= threshold` (a high ratio,
  e.g. most recorded calls detached). Exact threshold pinned during implementation.

Both are pure counts of object variants in `invokedCallStack` after the scan — no GC, no
timing, no MB. They fail iff detach did not happen (AST pinning reintroduced).

**REPORT — never asserted (manual-inspection view):**

- `System.gc()` (best-effort) then `MemoryMXBean` heap-used delta across the scan.
- Wall-clock time for the scan phase.
- Raw `CallContextStats` (`retainedWithTree`, `detached`, `total`, `buckets`) and the corpus
  size (`files`, `units`).

Printed to stdout in a single clearly-labelled block so a human can compare runs across
branches. No assertion references these values.

## Build configuration

Add `<excludedGroups>performance</excludedGroups>` to the `maven-surefire-plugin`
configuration in the parent `pom.xml` (currently declared with no `<configuration>`). Effect:

- `mvn test` / `mvn package` — skips the `performance`-tagged test (CI unaffected).
- `mvn test -Dgroups=performance -pl java` — runs it.

## Placement

- `java/src/test/java/com/ibm/plugin/perf/CallStackHeapPerfTest.java`
- `java/src/test/java/com/ibm/plugin/perf/CryptoCorpusGenerator.java`

The `java` module is required because the corpus uses JCA/BouncyCastle APIs (must be on the
test classpath to resolve) and the test uses sonar-java `CheckVerifier`.

## Data flow

```
CryptoCorpusGenerator.generate(N)              -> temp dir of .java (wrapper+caller units)
  -> compileToClasspath(sources)               -> classes dir
  -> CheckVerifier.onFiles(...).withClassPath(classes).withChecks(this).verifyIssues()
       -> engine records CallContexts (RetainedCall) as detections fire
       -> at each leaveFile, detachCallsForFile swaps detachable calls -> DetachedCall
  -> JavaAggregator.getLanguageSupport().callContextStats()
       -> ASSERT retainedWithTree <= bound, detachedRatio >= threshold
       -> REPORT heap delta, time, raw counts (stdout, not asserted)
```

## Validating the harness itself

The structural assertion is only worth committing if it actually discriminates:

1. **Passes on `feat/callstack-ast-detach`** — with detach live, `retainedWithTree` stays
   bounded and `detachedRatio` is high.
2. **Would fail if detach were disabled** — during development only, temporarily neutralize
   `CallStackAgent.detachCallsForFile` (make it a no-op) and confirm the test **fails**
   (`retainedWithTree` grows with corpus size). This neutralization is a local sanity check,
   **not committed**.

Both are recorded as explicit implementation steps in the plan.

## Out of scope

- Reproducing the literal ~7 GB keycloak number — remains the documented manual
  `mvn sonar:sonar` route; the test's javadoc points to
  `docs/superpowers/plans/2026-07-05-callstack-hooks-heap-reduction.md` for that.
- Any assertion on measured heap MB (report-only, to avoid machine/GC flake).
- Python and Go corpora — Java-only, where the term was measured and where the detach fix
  lives.
- Automating docker/SonarQube end-to-end.

## Open parameters (pinned during implementation)

- Default `perf.corpus.files` (small enough for a few-seconds manual run, large enough to
  make retention visible — candidate ~200).
- Exact `retainedWithTree` bound formula and `detachedRatio` threshold (derived from the
  generator's unit count and confirmed empirically in the harness-validation step).
- Which JCA APIs to rotate across units (at least `Cipher`, `KeyGenerator`, `MessageDigest`
  — all already covered by existing Java detection rules).
