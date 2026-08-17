# Crypto Behavior Taxonomy in CBOM — Design

**Date:** 2026-07-03
**Status:** Experimental feature — design approved, pending implementation plan
**Module ownership:** `output` (mapping + emission), `java` (curated new detection)

## 1. Summary

Attach CycloneDX 2.0-dev **cryptographic behavior** information to the generated CBOM. The
behaviors describe the **scanned software as a whole**: the CBOM already inventories all crypto
assets in the software, and the software *behaves* cryptographically (it encrypts data, signs data,
hashes passwords, …). We derive a behavior for each detected crypto asset where possible, then emit
the **union** of those behaviors once, as a property on the BOM's `metadata.component`.

This is **experimental**: the CycloneDX 2.0 threat-modeling taxonomy is still a draft. To stay
self-contained as the standard evolves, we bundle a **local copy** of the taxonomy (JSON resource)
and emit behaviors as a namespaced, non-standard property rather than as first-class schema fields.

### Reference

- Taxonomy source (draft): CycloneDX `2.0-dev-threatmodeling` branch,
  `schema/behavior-taxonomy.schema.json`, the `security:cryptography:*` enum (50 values).
- Example values: `encryptsData`, `decryptsData`, `signsData`, `verifiesSignature`, `hashesData`,
  `hashesPassword`, `generatesKey`, `generatesRandomValue`, `exchangesKey`, `wrapsKey`,
  `ensuresConfidentiality`, `ensuresIntegrity`, `ensuresNonRepudiation`, `authenticates`.

## 2. Goals / Non-goals

**Goals**
- Derive a cryptographic behavior for each detected asset where a confident mapping exists.
- Aggregate all detected behaviors and emit them once on `bom.metadata.component.properties`.
- Bundle a local, verbatim snapshot of the draft taxonomy so the feature is self-contained.
- Add a small, high-confidence set of *new/rewired* detections to unlock two extra behaviors.
- Keep the feature additive and trivially removable (output-layer only, plus isolated detection).

**Non-goals (deferred, documented as future work)**
- KeyStore key-lifecycle behaviors (`storesKey`, `retrievesKey`, `destroysKey`, `rotatesKey`) —
  require a new engine detection context, rules, model node, and mapper.
- Data-context behaviors (`encryptsDataAtRest` / `encryptsDataInTransit` / `encryptsDisk`, and the
  `decrypts*` equivalents) — require data-flow / taint analysis the engine does not have.
- PKI / certificate behaviors (`validatesCertificate`, `checksRevocation`, `issuesCertificate`,
  `revokesCertificate`, `presentsClientCertificate`, `presentsServerCertificate`).
- Per-asset behavior attribution in the output (we emit software-level aggregate only).

## 3. Design decisions (locked)

| Decision | Choice |
|---|---|
| Mapping source | **Operation-first, coarse**, maximizing precision from existing context (Functionality node + primitive kind + cipher opmode + mode). |
| Behavior categories | **Operational + security-goal** (both). |
| New-detection ambition | **Mapping + curated key-lifecycle-adjacent detections** (`wrapsKey`, `generatesRandomValue`); KeyStore deferred. |
| Output shape | **Single property, comma-separated list** of behavior identifiers. |
| Output location | **`bom.metadata.component.properties`** (software-level aggregate), *not* per-component. |
| Architecture | **Output-layer mapper** — no changes to the model/enricher pipeline for the mapping itself. |

## 4. Architecture & components

Data flow (additive to the existing pipeline):

```
detected asset (INode tree, post-enrich)
   → CryptoBehaviorMapper.map(asset)          # per asset
   → Set<CryptoBehavior>
   → union into a scan-wide Set<CryptoBehavior> accumulator (CBOMOutputFile)
   → CBOMOutputFile.getBom(): create metadata.component, attach ONE aggregate property
```

### 4.1 `crypto-behavior-taxonomy.json` (resource, `output` module)

A verbatim local copy of the draft taxonomy under
`output/src/main/resources/`. Contains the `security:cryptography:*` entries with, per behavior:
`identifier` (full colon-delimited id), `name` (leaf), `category`, and `description` (copied from the
schema's `meta:enum`). This is the authoritative "standard snapshot" for the experiment.

### 4.2 `CryptoBehavior` enum (`output` module)

Typed handles for the identifiers we actually emit (a subset of the 50). Each value exposes
`fullId()` → `"security:cryptography:<name>"`. A unit test asserts every enum value's `fullId()` is
present in `crypto-behavior-taxonomy.json`, keeping code and snapshot in sync.

### 4.3 `CryptoBehaviorMapper` (`output` module)

Pure, total function:

```java
Set<CryptoBehavior> map(INode asset);
```

Reads only data already on the asset tree:
- `Functionality` children (`Encrypt, Decrypt, Sign, Verify, Digest, Tag, Generate, KeyGeneration,
  KeyDerivation, Encapsulate, Decapsulate`),
- the asset's primitive `kind` (`BlockCipher, StreamCipher, Cipher, AuthenticatedEncryption, Mac,
  MessageDigest, Signature, KeyAgreement, PublicKeyEncryption, KeyDerivationFunction,
  PasswordBasedKeyDerivationFunction, PasswordBasedEncryption, KeyEncapsulationMechanism,
  PseudorandomNumberGenerator, …`),
- cipher opmode / `CipherAction` (to disambiguate wrap/unwrap),
- mode where relevant.

Never throws. An asset it cannot map returns an empty set (no wrong behavior emitted).

### 4.4 Output integration (`CBOMOutputFile`, `output` module)

- Add a scan-wide accumulator field `Set<CryptoBehavior> aggregatedBehaviors`.
- In each `create*Component(...)` method (`createAlgorithmComponent`, `createKeyComponent`,
  `createProtocolComponent`, `createCipherSuiteComponent`, `createRelatedCryptoMaterialComponent`),
  call `CryptoBehaviorMapper.map(node)` and add the result to the accumulator.
- In `getBom()` (metadata-assembly choke point): the current code sets `metadata` (timestamp +
  tool info) but **does not set `metadata.component`**. Create one:
  - `Component softwareComponent = new Component();`
  - `softwareComponent.setType(Component.Type.APPLICATION);`
  - `softwareComponent.setName(<scanned software name if available, else "application">);`
  - If `aggregatedBehaviors` is non-empty, attach exactly one property:
    - `name = "cbomkit:crypto:behavior"`
    - `value` = the accumulator mapped to `fullId()`, **deduped, sorted, joined with `,`**.
  - `metadata.setComponent(softwareComponent);`
- Emit nothing when the accumulator is empty (no property, and no empty component solely for it).

Namespace rationale: `cbomkit:` marks the property as an experimental, tool-specific extension so no
consumer mistakes it for a ratified CycloneDX field.

### 4.5 Curated detection changes (`java` module)

Two behaviors need signal the mapper can read; both are cheap relative to KeyStore.

**`generatesRandomValue`** — the `java/.../rules/detection/random/` package (`SecureRandomGetInstance`)
exists but is **orphaned** (never aggregated in `JavaDetectionRules`) and covers only the seed
constructor / `setSeed`. Work:
- Wire the `random` bundle into `JavaDetectionRules.rules()`.
- Extend it to detect `SecureRandom.getInstance(...)` / `SecureRandom.getInstanceStrong()` (and
  DRBG algorithm names) so a `PseudorandomNumberGenerator` asset with a `Generate` functionality is
  produced, which the mapper maps to `generatesRandomValue`.

**`wrapsKey`** — `Cipher.wrap` is already detected (`CipherAction.WRAP`) and `WRAP_MODE(3)` /
`UNWRAP_MODE(4)` opmodes already produce signals (`JcaCipherOperationModeMapper` currently maps
`3→Encapsulate, 4→Decapsulate`). Work:
- Ensure `Cipher.unwrap` is also detected (add the rule if missing) so unwrap surfaces a signal.
- The mapper distinguishes `Encapsulate`/`Decapsulate` **on a `Cipher`** (→ `wrapsKey`) from
  `Encapsulate`/`Decapsulate` **on a `KeyEncapsulationMechanism`** (→ `exchangesKey`) using the
  primitive kind. No change to the existing `cryptoFunctions` output is required.

## 5. Mapping table

Operation-first; primitive kind disambiguates and adds security-goal behaviors. When an asset has
**no** `Functionality` child, fall back to the plausible operational set implied by its primitive.

| Detected signal | Emitted behavior(s) |
|---|---|
| `Encrypt` on cipher / PKE / AE | `encryptsData`, `ensuresConfidentiality` |
| `Decrypt` on cipher / PKE / AE | `decryptsData`, `ensuresConfidentiality` |
| `Encapsulate` / `Decapsulate` on **Cipher** (wrap/unwrap) | `wrapsKey` |
| `Encapsulate` / `Decapsulate` on **KEM** | `exchangesKey`, `ensuresConfidentiality` |
| `KeyAgreement` primitive | `exchangesKey` |
| `Sign` on Signature | `signsData`, `ensuresIntegrity`, `ensuresNonRepudiation` |
| `Verify` on Signature | `verifiesSignature`, `ensuresIntegrity` |
| `Digest` on MessageDigest | `hashesData`, `ensuresIntegrity` |
| `Tag` on Mac | `authenticates`, `ensuresIntegrity` |
| `Generate` on PRNG / DRBG | `generatesRandomValue` |
| `KeyGeneration` | `generatesKey` |
| `KeyDerivation` on password-based KDF / PBE | `hashesPassword` |
| `KeyDerivation` on generic KDF | `generatesKey` *(approximate — see gaps)* |

**Primitive-only fallback** (no `Functionality` child present):

| Primitive kind | Inferred behavior(s) |
|---|---|
| `BlockCipher` / `StreamCipher` / `Cipher` | `encryptsData`, `decryptsData`, `ensuresConfidentiality` |
| `AuthenticatedEncryption` | `encryptsData`, `decryptsData`, `ensuresConfidentiality`, `ensuresIntegrity` |
| `PublicKeyEncryption` | `encryptsData`, `decryptsData`, `ensuresConfidentiality` |
| `Signature` | `signsData`, `verifiesSignature`, `ensuresIntegrity`, `ensuresNonRepudiation` |
| `MessageDigest` | `hashesData`, `ensuresIntegrity` |
| `Mac` | `authenticates`, `ensuresIntegrity` |
| `KeyAgreement` | `exchangesKey` |
| `KeyEncapsulationMechanism` | `exchangesKey`, `ensuresConfidentiality` |
| `PasswordBasedKeyDerivationFunction` / `PasswordBasedEncryption` | `hashesPassword` |
| `KeyDerivationFunction` | `generatesKey` *(approximate)* |
| `PseudorandomNumberGenerator` | `generatesRandomValue` |

### 5.1 Known taxonomy gaps (documented, honest)

- **MAC** has no operational "computesMac"/"tagsData" verb in the taxonomy; we emit the goal-level
  `authenticates` + `ensuresIntegrity` instead.
- **Generic KDF** (e.g. HKDF) has no "deriveKey" value; approximated as `generatesKey`. Flagged so a
  future taxonomy revision can refine it.

These gaps are captured in the `CryptoBehaviorMapper` as comments referencing this section.

## 6. Error handling

- `CryptoBehaviorMapper` is total: unknown/unsupported primitive or functionality → empty set,
  never an exception and never a guessed behavior.
- Empty scan-wide accumulator → no property emitted.
- Optional `DEBUG` log listing asset kinds that produced no behavior, to guide future mapping work.

## 7. Testing

- **`CryptoBehaviorMapper` unit tests** across representative assets: AES encrypt / decrypt / wrap,
  RSA sign / verify / encrypt, SHA-256 digest, HMAC, ECDH, PBKDF2, ML-KEM, SecureRandom, plus a
  primitive-only asset (no functionality) exercising the fallback table.
- **Enum ↔ JSON sync test**: every `CryptoBehavior.fullId()` exists in
  `crypto-behavior-taxonomy.json`.
- **Detection tests** (`TestBase` + `CheckVerifier`) for the rewired random detection and the
  wrap/unwrap detection.
- **CBOM integration test**: a source file using AES-encrypt + SHA-256 + HMAC produces a BOM whose
  `metadata.component.properties` contains exactly one `cbomkit:crypto:behavior` property with value
  `security:cryptography:authenticates,security:cryptography:encryptsData,security:cryptography:ensuresConfidentiality,security:cryptography:ensuresIntegrity,security:cryptography:hashesData`
  (deduped, sorted). Assert the property is absent when no crypto is detected.

## 8. Future work

- KeyStore key-lifecycle behaviors via a new `KeyStore`/certificate detection context.
- Data-context behaviors (`*DataAtRest` / `*DataInTransit` / `*Disk`) via call-site heuristics
  (`CipherInputStream`/`CipherOutputStream`, `KeyStore.load/store`, `SSLSocket` streams) — coarse
  heuristic only; true provenance needs data-flow analysis.
- PKI / certificate behaviors (`validatesCertificate`, `checksRevocation`, etc.).
- Promote from an experimental namespaced property to first-class CycloneDX fields once the 2.0
  taxonomy is ratified.
