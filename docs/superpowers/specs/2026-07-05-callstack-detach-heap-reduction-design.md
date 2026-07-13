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
   - *Consequence:* the produced `IValue`'s location must not pin the AST. We satisfy this **without changing the value model** by using a synthetic detached `SyntaxToken` (see §4).

## Keeping `T = Tree` (no value-model change)

An earlier reading of point 3 suggested every model value would need a `Location` abstraction (re-typing 27 model classes + 27 factories). That is **not necessary**. The value model's location `T` stays `Tree`; we supply a **synthetic detached `Tree`** for cross-file detections:

- `org.sonar.plugins.java.api.location.Position.at(int,int)` and `Range.at(...)` are public static factories producing AST-free coordinate objects; `SyntaxToken` is a small interface (`text/trivias/line/column/range` + `Tree`'s `is/accept/parent/firstToken/lastToken/kind`).
- A `DetachedSyntaxToken implements SyntaxToken` backed by captured primitives (line, column offsets, and the record-time keywords) returns `parent() == null` and `firstToken()/lastToken() == this`, so it pins nothing.
- The existing factories build `IValue<Tree>` with this token as the location, unchanged. Scope stays essentially within callstack/hooks + one new token class + a single translator branch. The plan's "strictly callstack/hooks" spirit holds.

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
  - **pre-resolved arguments:** for each argument index, the raw resolved value(s) (`Object`) plus captured location primitives (line, offset, keywords) for a `DetachedSyntaxToken` (see §4). If *any* argument fails to pre-resolve at record time, the call is treated as non-detachable and keeps its tree (fallback) — never a silent per-argument drop;
  - for enum accesses: the enum class name plus a snapshot map `{constantName → resolvedValue + location primitives}` (fire-time `EnumHook` selection picks by name).

Match uses the keys; the argument/enum snapshots feed fire-time replay. No `Tree` and no `JavaFileScannerContext` are retained → the file AST becomes GC-eligible after `leaveFile`.

### 3. Fire-time replay

`onNewHookSubscription` and `HookRepository.update` match against the record's keys instead of a tree. On a match of a `DetachedCall`, `DetectionStoreWithHook` skips `extractArgumentFromMethodCaller`/`resolveValuesInInnerScope` and instead takes the pre-resolved snapshot for the hook's parameter index, applies the hook's factory to it, and proceeds through `handleNextRulesForMethodHooks` as today (that path visits `hook.methodDefinition()`, from the hook's own file, and is unaffected by detachment). `RetainedCall`s replay exactly as today.

### 4. Detached location via synthetic `SyntaxToken` (no model change)

`getLocation()` keeps returning `Tree`; for a detached call we hand the factory a `DetachedSyntaxToken` instead of a real leaf tree:

- **New class** `DetachedSyntaxToken implements SyntaxToken` (engine, `com.ibm.engine…`): fields = start/end line + column offsets and the record-time `keywords`. `range()` → `Range.at(Position.at(line, col), Position.at(endLine, endCol))`; `firstToken()/lastToken()` → `this`; `kind()` → `Tree.Kind.TOKEN`; `parent()` → `null`; `accept()` → no-op; `text()` → the resolved value string; `trivias()` → empty. Value `equals/hashCode` over the fields (model `equals` compares `getLocation()`).
- **Record time:** while the argument's leaf tree is live, capture (line, columnOffset, end position, keywords) — computed by the *same* logic `JavaTranslator.getDetectionContextFrom` uses (`JavaTranslator.java:170`) — and store the primitives in the `DetachedCall`. No `Tree`/`Range`/`Position` object is retained (store ints), so nothing pins the AST.
- **Fire time:** build `new ResolvedValue<>(rawValue, new DetachedSyntaxToken(...))` and run the existing factory unchanged → `IValue<Tree>` whose location pins nothing.
- **One translator branch:** `JavaTranslator.getDetectionContextFrom` gets a leading `if (location instanceof DetachedSyntaxToken d) return new DetectionLocation(filePath, d.line(), d.offset(), d.keywords(), bundle);`. This preserves `keywords`/`additionalContext` fidelity exactly (they were computed from the live tree at record time). Python/Go never produce a `DetachedSyntaxToken`, so their translators are untouched.

Zero edits to the 27 model classes, 27 factories, and `ResolvedValue`. The change is one new class + one translator branch, plus the record/replay wiring.

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
- `engine/.../callstack/DetachedSyntaxToken.java` — NEW (synthetic `SyntaxToken`, §4).
- `engine/.../detection/DetectionStoreWithHook.java` — detached replay branch (build `ResolvedValue` from snapshot + `DetachedSyntaxToken`, skip `extractArgumentFromMethodCaller`/`resolveValuesInInnerScope`).
- `engine/.../language/java/JavaDetectionEngine.java` — record-time pre-resolution + `NEW_ARRAY` detection + capture location primitives.
- `engine/.../language/ILanguageSupport.java` (or `ILanguageTranslation.java`) — `isDetachableCall` predicate (default: not detachable → Python/Go keep trees).
- `java/.../translation/translator/JavaTranslator.java` — leading `DetachedSyntaxToken` branch in `getDetectionContextFrom` (Python/Go translators untouched).
- `java/src/test/files/...` + a new multi-file `CheckVerifier` test — NEW (see Verification).

No edits to the 27 `engine/.../model/*.java`, the 27 `engine/.../model/factory/*.java`, `ResolvedValue.java`, or the Python/Go engines/translators.

## Verification

- **Cross-file regression guard (new, does not exist today):** a multi-file `CheckVerifier` test where a hook created in file B resolves a call recorded in file A. Must cover **both** a detached argument (literal / constant / field / nested-call) **and** a tree-fallback argument (`NEW_ARRAY`/size), asserting both still detect.
- `mvn test -pl engine` and `mvn test -pl java` stay green throughout (run `mvn spotless:apply` before commits; restore `JsonCipherSuites` if Spotless truncates it).
- **Heap profile:** scan a large project (e.g. keycloak via `mvn sonar:sonar`, or supply `sonar.java.libraries`) under a constrained `MAVEN_OPTS="-Xmx<low>"`; capture `jmap -histo` before/after and record the drop in retained `CallContext`/AST and peak heap. Types must resolve (source-only scans fire `addCall` zero times).

## Risks & open implementation questions

- **`DetachedSyntaxToken` consumer safety (top risk):** the synthetic token returns `parent() == null` and a no-op `accept()`. This is safe only if every consumer of a value's `getLocation()` reads at most `firstToken()/lastToken()/kind()/range()`. Verified today: the sole *production* consumer is `getDetectionContextFrom`; production CBOM output does not `reportIssue` on value locations (that path is test-only). **Task:** audit all `IValue.getLocation()` consumers to confirm none navigate `parent()`/`accept()`/children, and make the new multi-file test's `asserts()` tolerant of detached locations.
- **Record-time pre-resolution fidelity:** must produce exactly the raw `ResolvedValue`s fire-time would, minus the `NEW_ARRAY`/`SizeFactory` case (kept on tree-fallback). Guard with a test that resolves the same argument both ways and asserts equality.
- **Enum snapshot completeness:** pre-resolving all enum constants at record time must match `resolveEnumValue`'s selection semantics; verify against existing enum-hook tests.
- **Location fidelity:** `keywords`/line/offset captured at record time must match what `getDetectionContextFrom` derives from the live tree, so CBOM occurrences (incl. `additionalContext`) are identical for detached vs. non-detached detections. Verify via an output-level test.
- **`filePath` origin for cross-file values:** confirm the translator receives file A's (call-site) path for a detached value, matching today's tree-derived behavior — this is independent of the token but must be checked on the cross-file path.

## Explicitly out of scope

- Python/Go detachment (kept on tree-fallback).
- The rule-graph construction OOM (`MethodMatcher.<init>`, tracked in #476/#477).
- Retention caps / lossy bounding from the original plan's Phase 1 (Task 5) — the detach makes them unnecessary; revisit only if post-detach record *count* itself proves a problem.
