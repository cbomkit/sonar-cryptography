# Call-stack Detach — Heap Reduction Design Spec

**Status:** Draft for review
**Date:** 2026-07-05
**Supersedes / refines:** `docs/superpowers/plans/2026-07-05-callstack-hooks-heap-reduction.md` (Phase 2 section)
**Decision this spec records:** go straight to the structural fix (detach recorded calls from the AST), skipping the plan's incremental Phase 1 filter/caps.

## Goal

Cut the project-lifetime heap held by `com.ibm.engine.callstack` on large scans — measured at ~179k retained `CallContext`s driving ~7 GB and climbing on a near-full keycloak scan, growing linearly and unbounded with project size — **without regressing cross-file detection**. Cross-file detection has no CI coverage today (every `CheckVerifier` test is single-file), so correctness preservation is the dominant constraint.

## Root cause (verified against current code)

One static `CallStackAgent` per language accumulates a `CallContext(tree, scanContext)` for **every recorded method invocation / enum access** across the whole scan and is released only at end-of-scan. `CallStackAgent.invokedCallStack` (`CallStackAgent.java:42`) is the holder.

The heap is dominated not by the *count* of `CallContext`s but by **per-file AST pinning**. Each `CallContext`:
- holds a `Tree` whose `parent()` chain reaches the file's `CompilationUnitTree`, and
- holds `JavaScanContext`, a `record(JavaFileScannerContext)` (`JavaScanContext.java:29`) that pins the whole file's AST a second way.

So a *single* surviving `CallContext` pins its entire file AST for the whole scan. Retained heap ≈ (distinct files with ≥1 recorded call) × (avg file AST size). Reducing the *count* (the plan's Phase 1 filter/caps) does not unpin a file that has even one surviving call — which is why this spec goes straight to detaching trees.

### The tree is load-bearing in three distinct places

A recorded call's tree is read at three points. All three must be handled to hold zero trees:

1. **Match** — `MethodMatcher.match(callContext.tree(), …)` in `onNewHookSubscription` (`CallStackAgent.java:107`) and via `HookRepository.update` → `hook.isInvocationOn(callContext, …)` (`HookRepository.java:117`). Reads invoked-object type, method name, parameter types off the tree.
   - *Snapshot-able at record time* — these three keys are all derivable while the file is live.

2. **Resolution input** — at fire time, `DetectionStoreWithHook.handleMethodInvocationHookWithParameterResolvement` (`DetectionStoreWithHook.java:124`) runs `extractArgumentFromMethodCaller` (`JavaDetectionEngine.java:121`) + `resolveValuesInInnerScope` (`:169`) on the **live** call-site argument tree and file symbol table.
   - *Verified narrowing (Java):* the parameter hook is always built with the 4-arg constructor (`JavaDetectionEngine.java:477`), so `expressionToResolve` is always `null` (`MethodInvocationHookWithParameterResolvement.java:43`). The cross-boundary branch never fires for Java. Fire-time resolution is therefore always "resolve the call-site argument directly," which is **fully reproducible at record time** because the file is live then.
   - *Verified narrowing (factory influence):* `valueFactory` steers traversal in exactly one place — `if (valueFactory instanceof SizeFactory<?>)` for `NEW_ARRAY` args (`JavaDetectionEngine.java:275`). Everywhere else the factory is threaded but not inspected; the raw `ResolvedValue` list is factory-independent, and the factory is applied *afterward* (`DetectionStoreWithHook.java:185`, `ValueDetection.toValue`).

3. **Detection output (location)** — the produced `IValue<T>.getLocation()` returns the tree (`IValue.java:26`; each of 27 model value classes stores its own `T location`). The sole production consumer is the translator: `JavaTranslator.getDetectionContextFrom` (`JavaTranslator.java:170`) reduces the tree to `DetectionLocation(filePath, lineNumber, columnOffset, keywords, bundle)` — every field derivable at record time.
   - *Consequence:* to emit a cross-file detection without holding the AST, the produced `IValue`'s location must be a tree-free snapshot. This forces a location-model change (see Scope Revision).

## Scope revision vs. the original plan

The plan constrained changes to "strictly callstack/hooks." **That constraint is not achievable for a faithful detach.** Point 3 above proves that every cross-file detection's produced value must carry a tree-free location, which touches the value-location model. This spec therefore expands scope to include a location abstraction across the model/factory/translator seam. This is the single largest cost of the work and the main review surface.

## Chosen architecture: Hybrid detach with tree-fallback

Detach (store a tree-free record) **only** for calls whose fire-time behavior is provably reproducible from a record-time snapshot; **keep the live tree** (today's behavior, that file stays pinned) for the residual. This guarantees no Java detection loss while unpinning the common case.

### 1. Detachability predicate (record time, Java)

At `addCall`, run the existing resolution over each argument with a `null` factory and record whether resolution descended into a `NEW_ARRAY`. A recorded call is **detachable** iff:
- it is a method invocation whose argument resolution did **not** touch a `NEW_ARRAY` (the only factory-steered case; a future `SizeFactory` hook would want the array size, not its elements), and
- (Java) always — since `expressionToResolve` is always null, there is no cross-boundary case.

Otherwise the call is **non-detachable** → keep the live `Tree` (fallback path, unchanged behavior). Python/Go are **always non-detachable** in this iteration (they use `expressionToResolve`; their semantics are out of scope) → they keep the tree exactly as today. The predicate lives in the language layer so the generic engine stays language-agnostic.

### 2. Detached record shape

Replace `CallContext(tree, scanContext)` with a sealed shape:
- `RetainedCall<T>(T tree, IScanContext scanContext)` — the fallback (non-detachable) case, identical to today.
- `DetachedCall` — tree-free, holding:
  - **match keys:** invoked-object `IType`, method name, parameter `IType`s (for `MethodMatcher` without a tree);
  - **pre-resolved arguments:** for each argument index, the raw resolved value(s) (`Object`) plus a `LocationSnapshot` (see §4). If *any* argument fails to pre-resolve at record time, the call is treated as non-detachable and keeps its tree (fallback) — never a silent per-argument drop;
  - for enum accesses: the enum class name plus a snapshot map `{constantName → resolvedValue + LocationSnapshot}` (fire-time `EnumHook` selection picks by name).

Match uses the keys; the argument/enum snapshots feed fire-time replay. No `Tree` and no `JavaFileScannerContext` are retained → the file AST becomes GC-eligible after `leaveFile`.

### 3. Fire-time replay

`onNewHookSubscription` and `HookRepository.update` match against the record's keys instead of a tree. On a match of a `DetachedCall`, `DetectionStoreWithHook` skips `extractArgumentFromMethodCaller`/`resolveValuesInInnerScope` and instead takes the pre-resolved snapshot for the hook's parameter index, applies the hook's factory to it, and proceeds through `handleNextRulesForMethodHooks` as today (that path visits `hook.methodDefinition()`, from the hook's own file, and is unaffected by detachment). `RetainedCall`s replay exactly as today.

### 4. Location abstraction (the model change)

Introduce an engine-level location carrier (no dependency on `mapper`):

```
sealed interface Location<T> permits TreeLocation, SnapshotLocation
  TreeLocation<T>(T tree)                                   // normal / fallback path
  SnapshotLocation<T>(String filePath, int line, int columnOffset, List<String> keywords)
```

- `ResolvedValue<O,T>` carries a `Location<T>` instead of a raw `T tree`. Normal resolution wraps the leaf tree in `TreeLocation`; record-time pre-resolution captures a `SnapshotLocation` (computed with the same logic `JavaTranslator.getDetectionContextFrom` uses today).
- The 27 model value classes store `Location<T>` instead of `T`; the 27 factories pass `resolvedValue.location()`.
- Translators handle both: `SnapshotLocation` → build `DetectionLocation` directly; `TreeLocation` → existing derivation. Python/Go always produce `TreeLocation`, so their behavior is unchanged.

This is mechanical but wide (~27 model + ~27 factory + 3 translator edits, plus `ResolvedValue` construction sites in the Java/Python/Go engines and tests that call `getLocation()`/`reportIssue`). It is exercised on the **main** cross-file path, not just edge cases.

### 5. Lossless cleanups folded in

- Delete the redundant `visitedTreeObjects` set (`CallStackAgent.java:45`); dedup within the per-name bucket (buckets are small once keys index them). Measured 100% redundant with `invokedCallStack`.
- Key-indexed subscription lookup in `onNewHookSubscription` (`CallStackAgent.java:101`): derive the name key from the hook value and scan only that bucket, with a fallback scan for multi-name/`ANY` matchers.

## Bounded, documented loss

- **Java:** zero detection loss by construction — the only non-reproducible cases (`NEW_ARRAY`/`SizeFactory`, cross-boundary `expressionToResolve`) are kept on the tree-fallback path. If measurement later shows the array-fallback set is large enough to matter for heap, a follow-up can pre-resolve both interpretations; not in this iteration.
- **Python/Go:** unchanged (always tree-fallback). No detach, no loss, no heap win for those languages yet.
- Any record-time resolution failure logs at DEBUG and falls back to keeping the tree, never to silent loss.

## Blast radius / files

- `engine/.../callstack/CallStackAgent.java` — key-indexed lookup; drop `visitedTreeObjects`; record `DetachedCall` vs `RetainedCall`; match against keys.
- `engine/.../callstack/CallContext.java` — becomes the sealed record family (`RetainedCall`/`DetachedCall`).
- `engine/.../detection/ResolvedValue.java` — carry `Location<T>`.
- `engine/.../model/Location.java` (+ `TreeLocation`, `SnapshotLocation`) — NEW.
- `engine/.../model/*.java` (27) + `engine/.../model/factory/*.java` (27) — location field/parameter type.
- `engine/.../detection/DetectionStoreWithHook.java` — detached replay branch.
- `engine/.../language/java/JavaDetectionEngine.java` — record-time pre-resolution + `NEW_ARRAY` detection; `ResolvedValue` construction.
- `engine/.../language/{python,go}/*DetectionEngine.java` — `ResolvedValue`/`TreeLocation` construction (behavior-preserving).
- `engine/.../language/ILanguageSupport.java` (or `ILanguageTranslation.java`) — `isDetachableCall` predicate (default: not detachable).
- `{java,python,go}/.../translation/translator/*Translator.java` — handle `SnapshotLocation`.
- `java/src/test/files/...` + a new multi-file `CheckVerifier` test — NEW (see Verification).

## Verification

- **Cross-file regression guard (new, does not exist today):** a multi-file `CheckVerifier` test where a hook created in file B resolves a call recorded in file A. Must cover **both** a detached argument (literal / constant / field / nested-call) **and** a tree-fallback argument (`NEW_ARRAY`/size), asserting both still detect.
- `mvn test -pl engine` and `mvn test -pl java` stay green throughout (run `mvn spotless:apply` before commits; restore `JsonCipherSuites` if Spotless truncates it).
- **Heap profile:** scan a large project (e.g. keycloak via `mvn sonar:sonar`, or supply `sonar.java.libraries`) under a constrained `MAVEN_OPTS="-Xmx<low>"`; capture `jmap -histo` before/after and record the drop in retained `CallContext`/AST and peak heap. Types must resolve (source-only scans fire `addCall` zero times).

## Risks & open implementation questions

- **Location-model diff size** is the top risk — wide but mechanical. Mitigate by landing it as an isolated, behavior-preserving commit (`TreeLocation` everywhere) before any detach logic, so it can be reviewed/tested independently.
- **Record-time pre-resolution fidelity:** must produce exactly the raw `ResolvedValue`s fire-time would, minus the `SizeFactory` case. Guard with a test that resolves the same argument both ways and asserts equality.
- **Enum snapshot completeness:** pre-resolving all enum constants at record time must match `resolveEnumValue`'s selection semantics; verify against existing enum-hook tests.
- **`SnapshotLocation` fidelity:** the `keywords`/line/offset must match what `getDetectionContextFrom` produces from the live tree, so CBOM occurrences are identical for detached vs. non-detached detections. Verify via an output-level test.
- **`filePath` origin for cross-file values:** confirm the detached value's `SnapshotLocation.filePath` is file A's (the call site), matching today's tree-derived behavior.

## Explicitly out of scope

- Python/Go detachment (kept on tree-fallback).
- The rule-graph construction OOM (`MethodMatcher.<init>`, tracked in #476/#477).
- Retention caps / lossy bounding from the original plan's Phase 1 (Task 5) — the detach makes them unnecessary; revisit only if post-detach record *count* itself proves a problem.
