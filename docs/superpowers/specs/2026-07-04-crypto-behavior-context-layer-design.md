# Crypto Behavior Taxonomy — Contextual Evidence Layer — Design

**Date:** 2026-07-04
**Status:** Experimental feature — design approved, pending implementation plan
**Builds on:** `2026-07-03-crypto-behavior-taxonomy-design.md` (base behavior taxonomy)
**Module ownership:** `engine` (new context kind), `java` (new AST detection + routing), `output` (evidence store consumption, inference, emission)

## 1. Summary

The base crypto-behavior feature derives a behavior for each detected **crypto asset** and emits the
union on `bom.metadata.component`. That is sound for operational verbs (`encryptsData`, `hashesData`)
and low-level goals (`ensuresIntegrity`), but it is too weak for **application-level** behaviors. The
canonical example: a `Mac` today yields `authenticates`, yet a MAC alone does not tell us the
application performs authentication in any protocol sense.

This feature adds a second, **scan-wide evidence dimension** — detected **non-crypto interfaces** the
application exposes (Phase 1: authentication / token: OAuth, SAML, JWT, principal identity) — and a
**two-tier inference engine** that combines crypto-derived behaviors with contextual evidence to
decide which behaviors to emit and at what **confidence**. App-level behaviors are **gated** behind a
required *primary* signal, so crypto alone can never assert them; weaker signals only *corroborate*.

This remains **experimental**, consistent with the base feature: behaviors are emitted as a
namespaced, non-standard property, and the draft CycloneDX 2.0 taxonomy snapshot stays the source of
truth for identifiers.

### The motivating fix

| | Before (base feature) | After (this feature) |
|---|---|---|
| MAC only | emits `authenticates` | **no** `authenticates` (suppressed — MAC only corroborates) |
| MAC + JWT-verify interface | emits `authenticates` (same as MAC only) | `authenticates=high` (gated primary present, MAC corroborates) |
| JWT-verify interface, no MAC | not detected | `authenticates=high`, `validatesToken=high` |

## 2. Goals / Non-goals

**Goals**
- Add a **general context layer** that both *qualifies* existing crypto-derived behaviors (gating) and
  *unlocks* new application-level behaviors that crypto alone cannot justify.
- Aggregate non-crypto contextual signals scan-wide **without polluting the crypto inventory** (no
  fake crypto components, no auth signals in the `Algorithm`/`Protocol` model).
- Introduce a **two-tier inference** model (required primary + corroborating) with a **discrete
  confidence** tag (`high` / `medium`).
- Phase 1: detect the **authentication / token** interface family via AST detection and wire it
  end-to-end to prove the mechanism.
- Keep it additive and consistent with the base feature's output location and experimental namespace.

**Non-goals (deferred)**
- **Phase 2 — dependency / import scan** as a *corroborating-only* source (see §9). Designed-for now,
  not built now.
- Certificate / TLS-client-auth behaviors (`presentsClientCertificate`, `validatesCertificate`,
  `checksRevocation`) and code-signing behaviors (`signsCode`, `verifiesCodeSignature`) — additional
  AST families deferred until the mechanism is proven on the authentication anchor.
- Per-asset behavior attribution (we emit the software-level aggregate only, as in the base feature).
- Continuous / numeric confidence scoring — we use two discrete levels, deliberately, to stay
  auditable (no hand-tuned weights to defend).

## 3. Design decisions (locked)

| Decision | Choice |
|---|---|
| Primary win | **General context layer** — gates existing behaviors *and* unlocks new app-level ones. |
| Signal sources | **AST detection (Phase 1)** + **dependency/import scan (Phase 2, deferred)**. Both code-derived; no external manifest, no SBOM-only inference. |
| Inference model | **Two-tier: required primary + corroborating**, with a **discrete confidence tag** (`high` / `medium`). Corroborating-only evidence stays *below the emit line*. |
| Integration style | **Separate evidence channel** — contextual signals bypass the crypto `INode` stream and land in a scan-wide `BehaviorEvidenceStore`; they never become crypto components. |
| Delivery | **Phased** — Phase 1 builds the evidence + inference core fed by AST detection; Phase 2 adds the dependency/import source into the same store. |
| Phase 1 scope | **Authentication / token family only** (`authenticates`, `validatesToken`, `usesIdentity`). |
| Output shape | **One property, confidence-suffixed list**, suffix delimiter `=` (ids already contain `:`). Applied uniformly to all behaviors. |
| Reuse | **Extend** `CBOMOutputFile` behavior emission; **build new** the evidence store + inference engine (no existing abstraction to reuse for those). |

## 4. Architecture & components

Data flow (additive to the base pipeline; the crypto path is unchanged up to emission):

```
AST auth-interface usage (new rules, java module)
   → Finding tagged with new AuthContext
   → JavaBaseDetectionRule.update(): branch —
        AuthContext findings  → BehaviorEvidenceStore  (scan-wide, NOT JavaAggregator)
        all other findings    → JavaAggregator          (existing crypto path, unchanged)
   → ScannerManager exposes BehaviorEvidenceStore alongside aggregated nodes
   → CBOMOutputFile.add(nodes): per-asset CryptoBehaviorMapper.map(node) as today
   → CBOMOutputFile.getBom():
        BehaviorInferenceEngine.infer(aggregatedCryptoBehaviors, authSignals)
           → Map<CryptoBehavior, Confidence>
        → ONE confidence-suffixed property on metadata.component
```

### 4.1 `AuthContext` (engine module)

New `IDetectionContext` mirroring `ProtocolContext` (which implements the interface directly and adds
`ISupportKind<Kind>`):

```java
public class AuthContext implements IDetectionContext, ISupportKind<AuthContext.Kind> {
    public enum Kind { JWT, OAUTH, SAML, PRINCIPAL, NONE }
    // type() → AuthContext.class; kind() → the Kind
}
```

`Kind` classifies the detected interface. It is *evidence metadata*, not a crypto asset kind.

### 4.2 AST detection rules (java module, new `rules/detection/auth/` package)

Built with the existing `DetectionRuleBuilder<Tree>` fluent pattern (as `ssl/` and `jca/` do),
`.buildForContext(new AuthContext(Kind.X))`, bundled and wired into `JavaDetectionRules.rules()`.
Rules match only `METHOD_INVOCATION / NEW_CLASS / ENUM` (the engine's visitor constraint), which the
Phase 1 primaries satisfy. Phase 1 primaries (curated, high-confidence; exact type/method list is an
implementation detail refined in the plan):

| Kind | Example interfaces (primaries) |
|---|---|
| `JWT` | jjwt `Jwts.parser()` / `parseClaimsJws`; Nimbus `SignedJWT.verify` / `JWTProcessor.process` |
| `OAUTH` | Spring Security `JwtDecoder`; OAuth2 resource-server token validation entry points |
| `SAML` | OpenSAML assertion / response consumption + validation |
| `PRINCIPAL` | `HttpServletRequest.getUserPrincipal`; `SecurityContext` / `Authentication` identity access |

Each match produces a `Finding` carrying a lightweight auth value plus the `AuthContext`. The value
factory yields `(kind, location)` — deliberately **not** a crypto model node.

### 4.3 `BehaviorEvidenceStore` (the scan-wide aggregator — "aggregate this information" core)

A scan-wide collector of contextual evidence, parallel in spirit to `JavaAggregator` /
`ScanStatistics` but holding **non-crypto** signals:

```java
record AuthSignal(AuthContext.Kind kind, Location location) {}
// store: Set<AuthSignal> (dedup by kind + location)
```

Routing: in `JavaBaseDetectionRule.update(Finding)`, branch on the finding's root context. If it is
`AuthContext`, extract `(kind, location)` straight into the evidence store and **skip** `INode`
translation and `JavaAggregator`. All other findings follow the existing crypto path unchanged.
Because the signal is captured directly from the finding, **no new mapper model node and no new
translator are required.**

Lifecycle mirrors the existing static aggregators (reset per scan). The store is exposed through
`ScannerManager` (alongside `getAggregatedNodes()`) and threaded into the output factory so
`CBOMOutputFile` can read it at emission time.

### 4.4 `BehaviorInferenceEngine` (output module, `behavior` package)

The single decision point. Pure, total function:

```java
Map<CryptoBehavior, Confidence> infer(
        Set<CryptoBehavior> cryptoBehaviors,   // union from CryptoBehaviorMapper across all assets
        Set<AuthSignal> authSignals);          // from BehaviorEvidenceStore

enum Confidence { HIGH, MEDIUM }               // discrete; no numeric weights
```

`CryptoBehaviorMapper` is unchanged and still runs per-asset; its aggregated output becomes **input
evidence** to the engine rather than being emitted directly. The engine applies the two-tier rules
(§5), then `CBOMOutputFile` formats the result.

### 4.5 Output integration (`CBOMOutputFile`, output module)

- Keep the property name `cbomkit:crypto:behavior` and its location
  (`metadata.component.properties`).
- At `getBom()`, call `BehaviorInferenceEngine.infer(aggregatedBehaviors, authSignals)` and format the
  returned map into the confidence-suffixed value (§6).
- **Restructure the emission gate:** today the synthetic `metadata.component` + property is created
  only when crypto behaviors are non-empty. Change it to create the component/property when the
  inference result is non-empty (i.e. crypto behaviors **or** contextual signals produced output).
- Emit nothing (no component solely for this) when the inference result is empty.

## 5. Two-tier inference rules (Phase 1)

**Primary** = required, gating signal. **Corroborating** = raises confidence / adds specificity but
never fires a behavior alone. Corroborating-only evidence stays below the emit line.

| Behavior | Primary (required) | Corroborating | Emitted |
|---|---|---|---|
| Crypto operational/goal (`encryptsData`, `decryptsData`, `hashesData`, `signsData`, `verifiesSignature`, `ensuresConfidentiality`, `ensuresIntegrity`, `ensuresNonRepudiation`, `generatesKey`, `generatesRandomValue`, `wrapsKey`, `exchangesKey`, `hashesPassword`) | the crypto asset itself (as in base feature) | — | `high` (as today) |
| `authenticates` | an auth interface: `JWT` / `OAUTH` / `SAML` / `PRINCIPAL` | a `Mac` or `Signature` crypto asset; a `PRINCIPAL` identity API | `high` when primary present |
| `validatesToken` | a token-verification interface (`JWT` / `OAUTH`) | — | `high` when primary present |
| `usesIdentity` | a `PRINCIPAL` identity API | — | `high` when primary present |

**Gating semantics (the core change):**
- `CryptoBehaviorMapper` still derives `authenticates` from a `Mac`. The inference engine **removes**
  that crypto-derived `authenticates` and re-emits it **only** if an auth primary is present. MAC-only
  → `authenticates` suppressed. `ensuresIntegrity` from the MAC is unaffected and still emits.
- All other crypto behaviors pass through unchanged.

**Confidence in Phase 1:** AST primaries are strong, so Phase 1 app-level behaviors emit `high`.
`medium` is *reserved* for weaker / corroborating-only evidence — primarily exercised in Phase 2
(dependency-presence). The field ships now so the output format is stable across phases.

## 6. Output shape

One property, unchanged name and location:

- `name = "cbomkit:crypto:behavior"`
- `value` = each behavior's `fullId()` suffixed with `=<confidence>`, **deduped, sorted, joined with
  `,`**. Suffix delimiter is `=` because identifiers already contain `:`.

Example (AES-encrypt + SHA-256 + HMAC + JWT-verify interface):

```
security:cryptography:authenticates=high,security:cryptography:encryptsData=high,security:cryptography:ensuresConfidentiality=high,security:cryptography:ensuresIntegrity=high,security:cryptography:hashesData=high,security:cryptography:validatesToken=high
```

The suffix is applied **uniformly** to every behavior (crypto and app-level) for a consistent format.
This changes the base feature's property value format; its integration test is updated accordingly
(§8).

## 7. Error handling

- `BehaviorInferenceEngine.infer` is total: unknown/insufficient evidence → the behavior is simply
  absent; never throws, never guesses.
- Auth findings with an unrecognized shape → not added to the store (no crash, no signal).
- Empty inference result → no property, no synthetic component solely for it.
- Optional `DEBUG` log listing auth signals seen and app-level behaviors suppressed for lack of a
  primary, to guide Phase 2 and future families.

## 8. Testing

- **`BehaviorInferenceEngine` unit tests** (the heart):
  - MAC only → **no** `authenticates`; `ensuresIntegrity` still present.
  - MAC + `JWT` signal → `authenticates=high`.
  - `JWT` signal, no MAC → `validatesToken=high` and `authenticates=high`.
  - `PRINCIPAL` signal → `usesIdentity=high`; corroborates `authenticates` when a primary is present.
  - Crypto-only asset set → unchanged pass-through at `high`.
- **Detection tests** (`TestBase` + `CheckVerifier`) for each new auth rule (JWT / OAuth / SAML /
  principal), asserting an `AuthContext` signal of the right `Kind` is produced.
- **Routing test**: an `AuthContext` finding lands in `BehaviorEvidenceStore` and does **not** appear
  in the crypto node aggregation / CBOM component inventory.
- **CBOM integration test**: a source file using AES-encrypt + SHA-256 + HMAC + a JWT-verify call
  produces exactly one `cbomkit:crypto:behavior` property with the suffixed, sorted value including
  `authenticates=high` and `validatesToken=high`; a second file with HMAC but **no** auth interface
  produces the same crypto behaviors but **omits** `authenticates`.
- **Update base behavior integration test** to the new `=<confidence>` suffix format.
- **Enum ↔ JSON sync test** (existing) continues to guard identifiers; new app-level behaviors
  (`validatesToken`, `usesIdentity`, `authenticates`) already exist in the snapshot.

## 9. Phase 2 (designed-for, deferred): dependency / import scan

A **corroborating-only** source feeding the same `BehaviorEvidenceStore`:
- The plugin currently has **no** access to imports or declared dependencies (verified). Two options,
  both net-new plumbing:
  - Extend `IScanContext` / `JavaScanContext` to expose the compilation unit's imports (add
    `Tree.Kind.IMPORT` visiting or read the `CompilationUnitTree`), yielding per-file import evidence
    with locations.
  - A manifest-scanning `PostJob` reading `pom.xml` / `build.gradle` via `FileSystem` (the existing
    `OutputFileJob` already receives a `PostJobContext`).
- Dependency/import presence is weak (presence ≠ usage), so it enters strictly as **corroborating**
  evidence and drives `medium`-confidence emissions — never a primary. The two-tier model and the
  confidence field already accommodate it, so Phase 2 adds a source, not a mechanism.

## 10. Future work

- Additional AST families once the anchor is proven: certificate / TLS-client-auth
  (`presentsClientCertificate`, `presentsServerCertificate`, `validatesCertificate`,
  `checksRevocation`) and code signing (`signsCode`, `verifiesCodeSignature`).
- Per-asset / per-interface evidence attribution (occurrences) if consumers need provenance.
- Promote from the experimental namespaced property to first-class CycloneDX fields once the 2.0
  taxonomy is ratified.

## 11. Notes / risks

- **Cross-file detection:** auth primaries are single method-invocation matches, not cross-file
  hook-resolved detections, so the per-file hook-release pitfall does not apply here. Detection tests
  are single-file, consistent with the suite.
- **Base format change:** applying the confidence suffix uniformly changes the existing
  `cbomkit:crypto:behavior` value; this is intentional and the base test is updated in lockstep. Any
  external consumer of the experimental property must parse the `=<confidence>` suffix.
