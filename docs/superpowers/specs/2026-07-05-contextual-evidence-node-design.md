# Contextual Evidence as an IR Node — Design (rework of the evidence channel)

**Date:** 2026-07-05
**Status:** Design approved, pending implementation plan
**Supersedes:** the `BehaviorEvidenceStore` sidecar in `2026-07-04-crypto-behavior-context-layer-design.md` (§4.3 and its routing/threading). Everything else in that spec (two-tier inference, gating, confidence-suffixed output, Phase-1 auth scope) stands.
**Module ownership:** `mapper` (new IR node), `java` (new context translator + wiring), `output` (evidence collection during `add()`).

## 1. Summary

The first implementation of the context layer collected auth-interface evidence in a `BehaviorEvidenceStore`
— a Java-only static store written by a special routing branch in `JavaBaseDetectionRule.update()` and
threaded into the output factory via a new argument. That is a **parallel channel** bolted alongside the
one every detection already uses, and it lives in a single language module even though contextual
evidence is a cross-cutting concern for all languages.

This rework removes that channel. Contextual evidence becomes a **first-class node in the scan's
intermediate representation** (the mapper `INode` model) and flows through the exact pipeline every
detected concept already uses: per-language detection rule → per-language context translator → `INode`
→ per-language `Aggregator` → `ScannerManager` → language-neutral output. "Cross-cutting across
languages" then falls out for free, because the seam (`List<INode>` at `ScannerManager`) is already
language-neutral.

**Reframe that motivates this:** the mapper model is *not* a registry of cryptographic assets — it is
the internal intermediate representation of everything the scan detects. It already holds non-asset
nodes (functionalities, key/IV/salt lengths, modes). A contextual-evidence node belongs there as
naturally as those do.

## 2. Goals / Non-goals

**Goals**
- Represent contextual evidence uniformly with every other detected concept — no special store,
  no special routing, no bespoke factory/threading.
- Be cross-language by construction: adding Go/Python auth detection later is "add a rule + a context
  translator," exactly like adding any crypto detection.
- Keep the node **generic** (`ContextualEvidence`), reusable for future non-auth evidence.
- Preserve the already-approved inference, gating, and confidence-suffixed output unchanged.

**Non-goals**
- Changing the two-tier inference logic or output format (kept verbatim from the prior spec).
- Adding Go/Python auth detection now (Phase 1 remains Java-only; the architecture is merely ready).
- Per-evidence occurrence attribution in the CBOM (deferred, as before).

## 3. Design decisions (locked)

| Decision | Choice |
|---|---|
| Evidence transport | **Model it as an `INode`** and ride the existing per-language pipeline. |
| Node shape | **Generic `ContextualEvidence extends Property`**, carrying one `String identifier` + `DetectionLocation`. Not a crypto asset; never emitted as a component. |
| Detection → node | A per-language `*AuthContextTranslator` maps an `AuthContext` finding to a `ContextualEvidence` node; wired into the language's `Translator` if/else chain like every other context. |
| Evidence vocabulary | Single source of truth stays `AuthContext.Kind` (engine). The node carries `kind.name()`; the output layer bridges the string back to `AuthContext.Kind` with a guarded `valueOf`. Node stays generic; the tested inference engine stays typed and unchanged. |
| Evidence collection | `CBOMOutputFile.add()` gains one branch that records a `ContextualEvidence` node into a self-collected `Set<AuthContext.Kind>`, before the `hasChildren()` fallback, creating no component. |
| Auth-only scans | Count as results (a scan detecting only an auth interface produces a CBOM with behavior metadata). Not filtered from statistics. |

## 4. Architecture & data flow

```
auth detection rule (produces AuthContext finding)          [unchanged; prior spec §4.2 / Task 5]
   → JavaAuthContextTranslator → ContextualEvidence(kind.name(), location)   [NEW]
   → reorganize + enrich (pass through inert — enrichTree only transforms matched types)
   → JavaAggregator → ScannerManager.getAggregatedNodes() → CBOMOutputFile.add()   [existing pipe]
   → add(): ContextualEvidence branch records kind into Set<AuthContext.Kind> authSignals  [NEW]
   → getBom(): BehaviorInferenceEngine.infer(aggregatedBehaviors, authSignals)   [unchanged; Task 4]
   → one confidence-suffixed property on metadata.component                       [unchanged]
```

### 4.1 `ContextualEvidence` (mapper model, new)

`public class ContextualEvidence extends Property` (the abstract `IProperty` base that manages
children/location/origin). Fields: the inherited machinery plus a `@Nonnull String identifier`.
- `ContextualEvidence(String identifier, DetectionLocation location)`.
- `String identifier()` accessor; `asString()` returns the identifier; `getKind()` →
  `ContextualEvidence.class`.
- Javadoc states plainly: a detected contextual fact about the scanned code, **not** a cryptographic
  asset; the output layer interprets it and never emits it as a component.

### 4.2 `JavaAuthContextTranslator` (java, new) + `JavaTranslator` wiring

`implements IContextTranslation<Tree>`. In `translate(...)`, read
`((AuthContext) detectionContext).kind()`; if it is not `NONE`, return
`Optional.of(new ContextualEvidence(kind.name(), detectionLocation))`, else `Optional.empty()`.
Add to `JavaTranslator`'s dispatch chain:

```java
} else if (detectionValueContext.is(AuthContext.class)) {
    return new JavaAuthContextTranslator()
            .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
}
```

(Go/Python get their own `*AuthContextTranslator` + one dispatch branch if and when they add auth
detection — the same per-language cost every crypto concept already pays.)

### 4.3 `CBOMOutputFile` (output, changed)

- Keep `aggregatedBehaviors` (crypto) and `inferenceEngine`; keep the no-arg constructor only.
- Add a field `Set<AuthContext.Kind> authSignals = EnumSet.noneOf(AuthContext.Kind.class)`.
- In `add(...)`, add — **before** the `else if (node.hasChildren())` fallback:

```java
} else if (node instanceof ContextualEvidence evidence) {
    recordContextualEvidence(evidence);
}
```

  where `recordContextualEvidence` does a guarded `AuthContext.Kind.valueOf(evidence.identifier())`
  (ignore unknown tokens, never throw) and adds the kind to `authSignals`. No component is created.
- `getBom()` unchanged from the prior Task 4: `inferenceEngine.infer(aggregatedBehaviors, authSignals)`
  → confidence-suffixed property.

## 5. What the rework reverts (from the current branch state)

| Item | Action |
|---|---|
| `BehaviorEvidenceStore` (java) | **Delete** (+ its test). |
| `JavaBaseDetectionRule.update()` routing branch | **Revert** to original (auth findings translate normally). |
| `IOutputFileFactory` / `CBOMOutputFileFactory` signature | **Revert** to `createOutputFormat(List<INode> nodes)`. |
| `ScannerManager` (getOutputFile arg + store reset) | **Revert** to original; delete `ScannerManagerBehaviorWiringTest`. |
| `CBOMOutputFile(Set<AuthContext.Kind>)` constructor | **Revert** to no-arg only; self-collect in `add()`. |

**Kept unchanged:** `AuthContext` (engine), `CryptoBehavior`/`Confidence` enums, `BehaviorInferenceEngine`
(+ tests, still typed on `AuthContext.Kind`), the auth detection rules + their test, and the
`getBom()` inference + confidence-suffix emission.

## 6. Error handling

- Translator: unknown/`NONE` kind → `Optional.empty()` (no node), never throws.
- `recordContextualEvidence`: unrecognized identifier → guarded `valueOf` catches and ignores it; the
  evidence is silently dropped, never a crash.
- Inference remains total (prior spec §7).

## 7. Testing

- **`ContextualEvidence` unit test** (mapper): identifier/asString/getKind; equality/hashCode per the
  `Property` idiom.
- **Enrich/reorganize passthrough test**: a `ContextualEvidence` node survives `Enricher.enrich` and the
  reorganizer unchanged (guards the "inert node" assumption).
- **`JavaAuthContextTranslator` test** (java): an `AuthContext(JWT)` finding translates to a
  `ContextualEvidence("JWT", …)` node; `NONE` → empty.
- **Detection test** (existing, retained): auth rules still emit `AuthContext` findings. Its `asserts()`
  now also confirms the translated node is a `ContextualEvidence` (nodes are no longer routed away).
- **`CBOMOutputFile` evidence test** (output, replaces the constructor-based one): building a scan with
  an AES-encrypt asset **plus** a `ContextualEvidence("JWT", …)` node yields a metadata property
  containing `authenticates=high` and `validatesToken=high`; the same scan without the evidence node
  omits them (gating). Confirms `add()` records evidence and creates no component for it.
- **Inference engine tests**: unchanged (still green).
- **Full `mvn clean package`**: all modules build; whole pipeline exercised end-to-end.

## 8. Notes / risks

- **`ContextualEvidence` in aggregated nodes:** it appears in `getAggregatedNodes()` and
  `ScanStatistics` counts; a scan with only an auth interface now reports results. This is intended
  (the app does authenticate) — a conscious behavior change, not filtered.
- **`add()` branch order:** the `ContextualEvidence` branch must precede the `node.hasChildren()`
  fallback, or the node is recursed/dropped.
- **Passthrough stages:** `enrichTree` only transforms nodes a matching enricher recognizes and the
  reorganizer only rewrites nodes matching a rule; an unknown `ContextualEvidence` leaf passes through
  untouched. Covered by the passthrough test above.
