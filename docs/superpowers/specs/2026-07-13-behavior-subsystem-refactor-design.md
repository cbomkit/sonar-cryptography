# Behavior Subsystem Refactor — Design

**Date:** 2026-07-13
**Status:** Design approved, pending implementation plan
**Builds on:** `2026-07-03-crypto-behavior-taxonomy-design.md`, `2026-07-04-crypto-behavior-context-layer-design.md`
**Module ownership:** `output` only (java-module AuthContext detection rules untouched)

## 1. Motivation

The behavior feature works, but its output-layer implementation has four problems:

1. **Mixed concerns.** `CBOMOutputFile` holds behavior state (`aggregatedBehaviors`,
   `authSignals`), accumulates behaviors inside `createAlgorithmComponent()`, parses
   `ContextualEvidence` identifiers back into `AuthContext.Kind` via `valueOf` in
   `recordContextualEvidence()`, and runs inference plus property formatting inside `getBom()`
   — five behavior touchpoints woven through BOM assembly.
2. **Asymmetric inference input.** `BehaviorInferenceEngine.infer(cryptoBehaviors, authSignals)`
   takes two inputs only because the `AUTHENTICATES` gating was bolted on after the mapper
   already emitted it: the engine strips the mapper's `AUTHENTICATES` and re-adds it when an
   auth primary exists. The "corroboration" the docstring describes is a no-op in code — the
   emitted result is simply `authenticates ⟺ auth primary present`.
3. **Extension cost.** Each future evidence family (certificates, code signing) would add
   another field to `CBOMOutputFile` and another parameter to `infer(...)`.
4. **Readability.** `CryptoBehaviorMapper` is two long if-chains encoding what is really the
   declarative mapping table from the base-feature spec §5.

## 2. Scope decisions (locked)

| Decision | Choice |
|---|---|
| Refactor scope | **Semantic cleanup allowed** — internal restructuring plus fixing how the gating is expressed; emitted CBOM stays identical, unit-test expectations may change. |
| Extensibility axes designed for | **New evidence families** (certs, code signing) and **per-asset attribution**. |
| Explicitly out of scope | New signal-source plumbing (Phase 2 dependency scan mechanics), confidence/weights, changing the `ContextualEvidence`-through-`INode`-stream channel (the scanner-level `BehaviorEvidenceStore` of the 2026-07-04 spec §4.3 stays rejected). |
| Approach | **A — self-contained behavior subsystem with a unified signal model** (over B: scanner-level store re-plumbing engine/java/python; over C: minimal extraction that keeps the two-input engine). |

## 3. Architecture

One idea: *everything the scan tells us is a signal; behaviors are inferred from the signal
set by an ordered list of rules.*

```
com.ibm.output.behavior/
├── CryptoBehavior.java          enum, moved unchanged (keeps fullId())
├── BehaviorSignals.java         immutable snapshot of everything observed
├── BehaviorCollector.java       the ONE object CBOMOutputFile talks to
├── CryptoBehaviorMapper.java    per-asset derivation, table-ized (§5)
├── IBehaviorRule.java           Set<CryptoBehavior> apply(BehaviorSignals)
└── rules/
    ├── CryptoBehaviorRule.java  passes through crypto-derived behaviors
    └── AuthInterfaceRule.java   owns authenticates/validatesToken/usesIdentity

com.ibm.output.cyclondx/
└── BehaviorMetadataWriter.java  property name, synthetic "application" component,
                                 comma-join formatting (the only CycloneDX-specific part)
```

The behavior taxonomy and inference are output-format-agnostic, hence the move out of
`cyclondx`. `BEHAVIOR_PROPERTY_NAME` moves from the mapper to `BehaviorMetadataWriter`
(emission concern).

### 3.1 BehaviorCollector

Replaces the four behavior fields/methods in `CBOMOutputFile`. Two operations:

- **`observe(INode node)`** — recognizes what a node contributes. An `Algorithm` runs through
  `CryptoBehaviorMapper`; a `ContextualEvidence` is parsed to an `AuthContext.Kind` (the
  `valueOf` try/catch moves here — unknown identifiers are silently skipped). All other nodes
  are ignored. Call sites in `CBOMOutputFile`: the `add()` dispatch branch for
  `ContextualEvidence`, and `createAlgorithmComponent()` — the single choke point all
  algorithm paths already flow through (top-level, nested recursion, protocol/cipher-suite
  constituents via the builder callback).
- **`inferBehaviors()`** — snapshots observations into a `BehaviorSignals` and unions the
  output of the rule registry (Enricher-style ordered `List<IBehaviorRule>`).

`CBOMOutputFile.getBom()` shrinks to:
`BehaviorMetadataWriter.attachIfPresent(metadata, collector.inferBehaviors())`.

### 3.2 BehaviorSignals

The single evidence container — the answer to "why does infer need both inputs" (it no longer
does). Today it carries the union of crypto-derived behaviors and the set of observed
`AuthContext.Kind`s. A future evidence family = one new field here + one new rule + one new
`observe` branch; `CBOMOutputFile` and existing rules are untouched.

**Per-asset attribution readiness:** `observe()` already runs per asset, so attribution later
means the collector keeps a per-node map internally and grows an accessor — a change local to
the collector, no structural change.

## 4. Inference semantics (the cleanup)

- `CryptoBehaviorMapper` **stops emitting `AUTHENTICATES` entirely.** `Mac`/`Tag` contribute
  `ENSURES_INTEGRITY` only. The strip-then-re-add dance in the engine is deleted, not
  relocated; `BehaviorInferenceEngine` is removed (its pass-through remainder becomes the
  trivial `CryptoBehaviorRule`).
- `AuthInterfaceRule` is a declarative per-kind contribution table, unioned over observed kinds:

```java
Map<AuthContext.Kind, Set<CryptoBehavior>> CONTRIBUTIONS = Map.of(
    JWT,       Set.of(AUTHENTICATES, VALIDATES_TOKEN),
    OAUTH,     Set.of(AUTHENTICATES, VALIDATES_TOKEN),
    SAML,      Set.of(AUTHENTICATES, VALIDATES_TOKEN),
    PRINCIPAL, Set.of(AUTHENTICATES, USES_IDENTITY),
    MTLS,      Set.of(AUTHENTICATES, USES_IDENTITY),
    API_KEY,   Set.of(AUTHENTICATES));
```

This is output-equivalent to the current `hasAuthPrimary`/`hasTokenPrimary`/`hasIdentity`
boolean chains (verified against `BehaviorInferenceEngine.java:53-76`). Adding a kind is one
map entry. Corroboration tiers stay expressible later — a rule sees the full `BehaviorSignals`
— but no corroboration machinery is built now (YAGNI; it currently has no observable effect).

## 5. Mapper table-ization

The two if-chains become two declarative tables driven by a small record and ~10 lines of loop:

```java
record OperationMapping(Class<? extends INode> operation,
                        Predicate<INode> when,        // IS_KEM, IS_PRNG, ...; ANY for unconditional
                        Set<CryptoBehavior> behaviors) {}
```

- **Operational pass** — all matching rows contribute. Conditional rows make the quirks
  visible as single lines, e.g. `Encapsulate + IS_KEM → EXCHANGES_KEY, ENSURES_CONFIDENTIALITY`
  vs `Encapsulate + IS_CIPHER → WRAPS_KEY` (the JCA `WRAP_MODE` case). Either/or cases are
  expressed as two rows with complementary predicates:
  `KeyDerivation + IS_PASSWORD_KDF → HASHES_PASSWORD` and
  `KeyDerivation + IS_PASSWORD_KDF.negate() → GENERATES_KEY` — no hidden control flow.
- **Fallback pass** — ordered list, **first matching primitive kind wins**, preserving the
  else-if semantics (`AuthenticatedEncryption` must precede `BlockCipher`; `Mac` fallback now
  yields `ENSURES_INTEGRITY` only, per §4).

The tables read as the base-feature spec §5 tables again, top to bottom.

## 6. Error handling

Unchanged guarantees, relocated:
- `observe()` is total: irrelevant nodes ignored; unknown `ContextualEvidence` identifiers
  silently skipped (existing behavior, now inside the collector where the vocabulary lives).
- `inferBehaviors()` never throws; empty signals → empty set → `BehaviorMetadataWriter` emits
  nothing (no synthetic component), exactly as today.
- Rules are independent; a rule contributing nothing is normal.

## 7. Testing

- `CryptoBehaviorMapperTest` — keep all scenarios; drop `AUTHENTICATES` expectations for
  Mac/Tag rows. Add one ordering test pinning `AuthenticatedEncryption` over `BlockCipher` in
  the fallback table (guards the first-match contract).
- `BehaviorInferenceEngineTest` → `AuthInterfaceRuleTest` + `BehaviorCollectorTest`: same §8
  scenarios from the context-layer spec (MAC-only suppression, MAC+JWT, JWT-only, PRINCIPAL,
  pass-through) expressed against `observe()`/`inferBehaviors()`. This also finally tests the
  `ContextualEvidence` → `Kind` parsing, currently untested inside `CBOMOutputFile`.
- `CryptoBehaviorMetadataTest` — unchanged; the proof the emitted CBOM is byte-identical.
  This is the regression anchor.
- `CryptoBehaviorTaxonomyTest` (enum↔JSON sync) — only the enum's package import changes.

## 8. Migration steps

All within the output module:
1. Create `com.ibm.output.behavior`; move enum + mapper; table-ize mapper.
2. Add `BehaviorSignals`, `IBehaviorRule`, the two rules, `BehaviorCollector`.
3. Replace the five behavior touchpoints in `CBOMOutputFile` with the two `observe()` call
   sites + the `BehaviorMetadataWriter` line in `getBom()`.
4. Delete `BehaviorInferenceEngine`; migrate/rename tests per §7.
5. Verify: `mvn test -pl output`, then the java-module integration tests that exercise the
   behavior property end-to-end.

## 9. Non-changes (deliberate)

- `ContextualEvidence` keeps flowing through the `INode` stream; no scanner-level store.
- Output shape unchanged: one `cbomkit:crypto:behavior` property on `metadata.component`,
  deduped/sorted/comma-joined `fullId()`s; emitted only when non-empty.
- No confidence scoring, no per-asset emission yet, no new detection rules.
