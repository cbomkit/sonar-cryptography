# Call-stack AST-Detach Heap Reduction — Implementation Record (as-built)

> **Status:** Implemented on branch `feat/callstack-ast-detach`. Full clean build green. One task
> (heap measurement) deferred. This document records what was actually built; it diverges
> substantially from the original step-by-step plan because several assumptions were corrected
> during execution (see "Divergences from the original plan").

**Goal:** Stop the per-language `CallStackAgent` from pinning whole-file ASTs for the entire scan
(the measured ~7 GB / ~179k-`CallContext` runtime leak) without regressing detection or SonarQube
issue reporting — same-file *or* cross-file.

**Outcome:** Recorded calls are detached from their AST when their file finishes analysis. A file's
AST becomes garbage-collectable after `leaveFile`, while cross-file hook matching continues from a
tree-free snapshot. Same-file detections keep full behavior; cross-file detections produce CBOM
nodes and raise SonarQube issues without pinning any AST.

**Tech stack:** Java 17, Maven multi-module, sonar-java 8.0.1, JUnit 5 + AssertJ + `CheckVerifier`.

---

## As-built architecture

A recorded call is a sealed `CallContext<R,T>`:
- `RetainedCall(T tree, IScanContext publisher, @Nullable DetachedCall detachedForm)` — holds the
  live tree; used while the call's file is being analyzed.
- `DetachedCall(IType invokedObjectType, String methodName, List<IType> parameterTypes,
  List<ArgSnapshot> arguments, DetachedScanContext publisher)` — tree-free.

**Lifecycle:**
1. **Record (file live):** `JavaDetectionEngine.recordCall` stores a `RetainedCall`. If the call is
   detachable (`isDetachableCall`), it also pre-builds the `DetachedCall` *now* (arguments resolved
   while the file's AST + symbols are live) and stashes it in `RetainedCall.detachedForm`.
2. **Same-file fire (file live):** hook detections during the file's own analysis match/replay
   through the `RetainedCall`'s live tree + context, so their SonarQube issues and value resolution
   are unchanged.
3. **`leaveFile`:** `JavaBaseDetectionRule.leaveFile` → `ILanguageSupport.notifyLeaveFile` →
   `CallStackAgent.detachCallsForFile(inputFile)` swaps each of that file's `RetainedCall`s for its
   `detachedForm`, dropping the tree → the file's AST is GC-eligible.
4. **Cross-file fire (file gone):** later hooks match the `DetachedCall` via
   `MethodMatcher.matchKeys(...)` and replay from its `ArgSnapshot`s. The detection value's location
   is an AST-free `DetachedSyntaxToken`; its SonarQube issue is raised via `SonarComponents` (see
   Reporting).

**Detachability (`JavaLanguageSupport.isDetachableCall`):** a `MethodInvocationTree` whose arguments
contain no `NEW_ARRAY` (the one value-factory-dependent resolution case, `SizeFactory`). It does
**not** require `methodSymbol().declaration() != null` — cross-file callees resolve via the binary
classpath, so `declaration()` is null for exactly the cross-file calls we must detach.

**Reporting (cross-file, no AST):** sonar-java's public issue API is entirely tree-based, and any
tree pins the AST. So cross-file detached issues are raised through the internal
`SonarComponents.reportIssue(new AnalyzerMessage(check, inputFile, TextSpan, message, 0))` —
`SonarComponents` is shared per scan and pins no AST. It is captured at record time and read
reflectively from the protected `DefaultModuleScannerContext.sonarComponents` field
(`JavaDetachedIssueReporter`, with a graceful null fallback to CBOM-only). `IDetachedIssueReporter`
abstracts this in the engine; `DetachedScanContext.reportIssue` delegates to it using the
`DetachedSyntaxToken`'s captured range.

---

## Files (as-built)

Engine (`engine/src/main/java/com/ibm/engine/`):
- `callstack/CallContext.java` — sealed interface (`permits RetainedCall, DetachedCall`).
- `callstack/RetainedCall.java` — NEW — `(tree, publisher, @Nullable detachedForm)`.
- `callstack/DetachedCall.java` — NEW — tree-free record.
- `callstack/ArgSnapshot.java` — NEW — per-argument resolved values + location.
- `callstack/DetachedSyntaxToken.java` — NEW — AST-free `SyntaxToken` (value location).
- `callstack/DetachedScanContext.java` — NEW — AST-free `IScanContext` (InputFile + path + reporter).
- `callstack/IDetachedIssueReporter.java` — NEW — engine-side reporting abstraction.
- `callstack/CallStackAgent.java` — variant-aware add/match; `detachCallsForFile`; key-indexed
  subscription lookup; `visitedTreeObjects` removed (per-bucket dedup).
- `detection/MethodMatcher.java` — `matchKeys(IType, name, List<IType>)` overload.
- `detection/DetectionStore.java`, `detection/DetectionStoreWithHook.java` — fire path carries
  `CallContext`; detached replay branch (`replayDetachedParameterHook`).
- `hooks/*` — `notify`/`onHookInvocation` carry `CallContext`; `isInvocationOn(CallContext)` matches
  `DetachedCall` via `matchKeys`.
- `language/ILanguageSupport.java` — `isDetachableCall`, `parameterIndexOf`, `notifyLeaveFile`
  defaults.
- `language/java/JavaLanguageSupport.java` — Java impls of the above.
- `language/java/JavaDetectionEngine.java` — `recordCall` / `buildDetachedCall` / `captureLocation`.
- `language/java/JavaDetachedIssueReporter.java` — NEW — `SonarComponents` reporter.

Java plugin (`java/src/`):
- `main/.../rules/detection/JavaBaseDetectionRule.java` — `leaveFile` hook.
- `test/files/rules/detection/crossfile/*` + `test/.../crossfile/CrossFileHookDetachTest.java`,
  `IsDetachableCallTest.java` — NEW — the first multi-file tests (compiled-classpath technique).

---

## Testing

**Cross-file test technique (new to the repo):** `CheckVerifier.onFiles(...)` alone does not give
sibling sources shared semantics, so cross-file callee types don't resolve and hooks never match
(why no multi-file test ever existed). Production resolves cross-file types via `sonar.java.binaries`
(the project is compiled first). Reproduced by compiling the fixtures to `.class` in-test and passing
the dir to `CheckVerifier.withClassPath(...)`. See `CrossFileHookDetachTest`.

**What the cross-file guard asserts:** all three detach branches resolve cross-file into the CBOM
(literal → detached, field-constant → detached, `new byte[]` → retained). The retained (array) case
also asserts its SonarQube issue via `verifyIssues`.

**`CheckVerifier` limitation (documented):** it reads issues only from the test context's
`getIssues()` (populated by `context.reportIssue`), not from `SonarComponents`. So cross-file
detached squid issues (retro-scan order) are production-correct but not `verifyIssues`-observable;
they are asserted via CBOM values instead.

---

## Divergences from the original plan (and why)

1. **Detach at `leaveFile`, not at record time.** Record-time detach routed same-file hook
   detections through the tree-free path, so they lost their live-context SonarQube issues and broke
   ~7 `rules/resolve` tests. Deferring to `leaveFile` keeps same-file detections fully live.
2. **`isDetachableCall` dropped the `declaration() != null` check.** That check (from the abandoned
   Phase-1 *filter* rationale) is null for every cross-file call (binary-classpath resolution), so it
   would have made cross-file calls non-detachable — silently defeating the heap goal.
3. **Cross-file reporting via internal `SonarComponents` + reflection.** The spec assumed
   `reportIssue` was off the path; it is not (`report()` yields issues). Public reporting is
   tree-based (AST-pinning), so the internal `SonarComponents` path was required.
4. **No explicit `JavaTranslator` branch for `DetachedSyntaxToken`.** Unnecessary — it flows through
   `getDetectionContextFrom`'s generic token path correctly.

---

## Remaining

- **Heap measurement (deferred):** scan a large compiled project (e.g. keycloak via `mvn
  sonar:sonar`, or supply `sonar.java.libraries`) under a constrained `MAVEN_OPTS="-Xmx<low>"`;
  capture `jmap -histo` before/after and record the drop in retained `CallContext`/AST and peak
  heap, versus the ~179k / ~7 GB baseline in
  `docs/superpowers/plans/2026-07-05-callstack-hooks-heap-reduction.md`. This is the piece that
  quantifies the win and should run before merge.

## Follow-ups worth a reviewer's eye

- `JavaDetachedIssueReporter` reflectively reads an internal sonar-java field — fragile across major
  upgrades (graceful null fallback mitigates). Consistent with the existing `ExpressionUtils` usage.
- Enum accesses, Python and Go remain on the always-retained path (unchanged) by design.
