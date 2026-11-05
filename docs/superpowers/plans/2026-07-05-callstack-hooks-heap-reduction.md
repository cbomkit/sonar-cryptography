# Call-stack / Hooks Heap Reduction Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Phase 2 is deferred pending the Phase 1 heap measurement — do not start it until the Task 6 profile is captured.

**Goal:** Cut the project-lifetime heap held by `com.ibm.engine.callstack` and `com.ibm.engine.hooks` on large scans, without regressing cross-file detection. Deliver a mostly-lossless trim + hard ceiling now (Phase 1), then a structural fix that stops pinning whole-file ASTs (Phase 2, scoped after measurement).

**Architecture:** One static `CallStackAgent`/`HookRepository`/`HookDetectionObservable` per language (held via `*Aggregator` static fields, `Handler.java:41-43`) accumulates state for the whole scan and is released only by the end-of-scan `ScannerManager.reset()` PostJob. Phase 1 shrinks what enters `invokedCallStack` and bounds its size; Phase 2 replaces retained live AST nodes with detached call records so per-file ASTs become GC-eligible.

**Tech Stack:** Java 17, Maven multi-module, sonar-java `CheckVerifier`, JUnit 5 + AssertJ.

## Context / Why

Large-project scans exhaust the heap. The documented OOM (`docs/TROUBLESHOOTING.md:138`) is rule-graph construction (`MethodMatcher.<init>`, ~520k objects) and is **out of scope** here (tracked in #476). This plan targets the *other* major term: call-stack/hooks state.

Heap holders (all project-lifetime, one static instance per language):
- `CallStackAgent.invokedCallStack` (`CallStackAgent.java:42`) — a `CallContext(tree, scanContext)` per **every method invocation and enum access in the whole project**.
- `CallStackAgent.visitedTreeObjects` (`CallStackAgent.java:45`) — a redundant dedup `Set<T>` duplicating those tree refs.
- `HookRepository.hookSet` + `HookDetectionObservable.listeners` — hooks/subscriptions, never pruned during a scan.

Dominant cost = **AST pinning**: SonarQube `Tree` nodes hold a `parent()` chain to the compilation unit and each `CallContext` also retains the file's `JavaFileScannerContext`, so retaining any one node pins that file's entire AST for the whole scan → effectively the whole project's AST is held at once.

**Measured (2026-07-05, keycloak-main via `mvn sonar:sonar` — compiled so types resolve and detections fire; instrumented `CallStackAgent`, SonarQube 26.1):**

| addCalls | retained `CallContext`s | buckets | peak used heap |
|---:|---:|---:|---:|
| 1,147,068 | 3,265 | ~500 | ~0.5 GB |
| 62,770,000 | 178,818 | 15,859 | **~7 GB** (scan not yet finished) |

- Growth is **perfectly linear and never plateaus** — ~2.85 retained per 1,000 `addCall`s (identical slope from 1M→63M calls). Because `Tree`/`CallContext` objects are per-file, distinct recorded call sites keep accumulating with project size, so the retained set (and pinned-AST heap) is **unbounded in scan size**. At ~63M calls it already held ~179k `CallContext`s and drove the heap to ~7 GB — enough to OOM a default-heap scanner.
- `addCall` is reached only inside *matched* detection-subtree traversal (not a global per-invocation visitor), and the dedup collapses ~63M calls to ~179k distinct trees (~0.28% retention) — but that is still linear in project size.
- `visitedTreeObjects.size()` **equals** `retainedCallContexts` at every sample → the dedup set is a 100% redundant duplicate (now ~179k entries). Confirms Task 3 is a free win.
- Caveat: a source-only scan (no `sonar.java.binaries`/`sonar.java.libraries`) resolves nothing → no detections → `addCall` fires 0 times → this term is 0. It only appears once types resolve (compiled project, or `sonar.java.libraries` supplied).

Hard constraint: cross-file resolution (`CallStackAgent.onNewHookSubscription:90`) replays the *entire accumulated* call stack so a hook created in file B resolves a call in file A. Naive per-file clearing silently drops cross-file detections and CI misses it (all rule tests are single-file). So retention cannot be scoped per file.

Load-bearing facts (verified):
- Method hooks are only created from **user methods with a source declaration** (`JavaDetectionEngine.java:418-419`, `declaration() != null`).
- The hook's matcher encodes the **specific enclosing-class FQN** and is `null` unless that class is source-declared (`JavaLanguageSupport.java:104-125`); match = `invokedObjectType.is(userClassFQN)` AND name AND params (`MethodMatcher.match:159`).
- ⇒ A recorded **library** call (object type is a library type, no source declaration) can never match any method hook. Recording it is pure waste.
- Enum accesses match a separate `EnumHook` path and must still be recorded.
- `onNewHookSubscription` ignores its hash key and scans **all** buckets (`CallStackAgent.java:101`) — CPU waste that also blocks per-bucket bounding.

Decisions (from user): bounded/measurable detection loss acceptable; scope strictly callstack/hooks; willing to invest in the structural fix.

## Global Constraints

- Java 17; module boundary: changes live in `engine` (+ Java language support), consumed by `java`/plugin.
- Apache 2.0 license header in every new `.java` file (copy from a neighbor). Run `mvn spotless:apply` before committing (restore `JsonCipherSuites` if Spotless truncates it — see memory note).
- Keep the generic engine language-agnostic: the "hook-eligible" predicate goes through the language layer (`ILanguageTranslation`/`ILanguageSupport`), not into generic engine code.
- Python/Go behavior must stay unchanged in Phase 1 (conservative default: record all) until their semantics are separately verified.
- `mvn test -pl engine` and `mvn test -pl java` stay green throughout.

---

## File Structure

- `engine/.../language/ILanguageTranslation.java` (or `ILanguageSupport.java`) — MODIFY — add `isHookEligibleCall(T)` predicate (default `true`).
- `engine/.../language/java/JavaLanguageSupport.java` — MODIFY — Java implementation (`declaration() != null` OR enum access).
- `engine/.../language/java/JavaDetectionEngine.java` — MODIFY — gate `addCallToCallStack` at the two record sites (`:100`, `:115`).
- `engine/.../callstack/CallStackAgent.java` — MODIFY — drop `visitedTreeObjects`; key-indexed subscription lookup; retention caps.
- `engine/.../callstack/CallContext.java` — MODIFY (Phase 2) — detached record shape.
- `engine/.../hooks/HookRepository.java`, `HookDetectionObservable.java` — MODIFY (Phase 2) — consume detached records.
- `java/src/test/files/...` + a new multi-file `CheckVerifier` test — CREATE — cross-file resolution regression guard.

---

## Phase 1 — Trim & bound (mostly lossless, ships first)

### Task 1: `isHookEligibleCall` predicate in the language layer
- [ ] Add `default boolean isHookEligibleCall(T tree) { return true; }` to `ILanguageTranslation` (or `ILanguageSupport`).
- [ ] Implement for Java in `JavaLanguageSupport`: return `true` for enum accesses (must stay recorded for `EnumHook`) and for method invocations whose `methodSymbol().declaration() != null`; `false` otherwise. Log at DEBUG when a call is skipped.
- [ ] Leave Python/Go on the default (`true`) — unchanged behavior.

### Task 2: Gate recording in the Java detection engine
- [ ] In `JavaDetectionEngine` at the two `addCallToCallStack` sites (`:100`, `:115`), skip the call when `!isHookEligibleCall(tree)`.
- [ ] Confirm losslessness: the only bounded edge is a user class inheriting a library method and being hooked via an override — document it and log at DEBUG. Everything else cannot match a method hook (matcher requires a specific user-class owner type).

### Task 3: Remove redundant `visitedTreeObjects`
- [ ] Delete the `visitedTreeObjects` field (`CallStackAgent.java:45`) and its use in `addedToCallContext:123`.
- [ ] Dedup within the per-name bucket list instead (buckets are small once Task 2 lands). Preserve the "return false if already present" contract so `notify` still fires only for genuinely new calls.

### Task 4: Key-indexed subscription lookup
- [ ] In `onNewHookSubscription` (`CallStackAgent.java:90-112`), derive the same name key used at insert (`getKeyFormT` logic) from the hook value and look up only that bucket instead of iterating `invokedCallStack.values()`.
- [ ] Keep the fallback correct for `ANY`/multi-name matchers (if the matcher can match multiple names, fall back to scanning — but the common single-name case is O(bucket)).

### Task 5: Retention caps (safety valve, bounded measurable loss)
- [ ] Add a per-name-bucket cap and a global `invokedCallStack` cap with sensible defaults, overridable via a plugin property.
- [ ] On overflow, stop recording new calls for that bucket and emit a single WARN naming the method + cap, so loss is explicit and measurable.

### Task 6: Verification for Phase 1
- [ ] Add a **multi-file** `CheckVerifier` test where a hook created in one file resolves a call in another (today's tests are all single-file). Assert it still passes with Tasks 1–5 applied — this is the cross-file regression guard.
- [ ] `mvn test -pl engine` and `mvn test -pl java` green.
- [ ] Heap profile: scan a large project (e.g. `client-encryption-java` from `docs/TROUBLESHOOTING.md`) with a constrained `MAVEN_OPTS="-Xmx<low>"`; capture `jmap -histo` before/after and record the drop in `CallContext` count + retained AST. **This measurement decides Phase 2 scope.**

---

## Phase 2 — Detach recorded calls from the AST (deferred; structural fix)

Start only after Task 6's profile confirms residual AST retention is the dominant remaining term.

**Idea:** Replace retained `CallContext(tree, scanContext)` with a **detached call record** capturing (a) the match keys `MethodMatcher` needs — invoked-object type, method name, parameter types — extracted eagerly at record time, and (b) a self-contained snapshot of the argument value(s) hook consumers read. After a file is analyzed nothing references its AST → the file's `JavaFileScannerContext`/AST is collected, removing the whole-project-AST pin.

**Bounded, documented loss:** replays needing full file-scope symbol resolution at hook-fire time (an argument that is a local/field requiring the file AST) are dropped and logged; literal/constant/enum/nested-call flows are preserved. Phase 1's filter keeps this surface small.

**Surface:** `CallContext`, `CallStackAgent` (record + replay), the match/replay contract in `HookRepository`/`HookDetectionObservable`, and how `DetectionStore` consumes a replayed call. Scope this as its own task-by-task section once measured.

**Verification:** re-run the Task 6 multi-file test + heap profile at a lower `-Xmx`; confirm the fallback logs fire only on the expected complex-flow cases.
