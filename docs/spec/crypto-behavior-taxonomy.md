# Experimental crypto behavior taxonomy

PR: [#494](https://github.com/cbomkit/sonar-cryptography/pull/494)

## 1. Purpose

Add a scan-wide summary of what the analyzed software does cryptographically to its
CBOM: encrypting data, wrapping keys, hashing passwords, validating tokens, and other
behaviors supported by detected evidence. The existing crypto inventory remains the
source for crypto operations; contextual authentication evidence supplies application
behaviors that crypto primitives alone cannot establish.

Identifiers come from the bundled snapshot of the CycloneDX `2.0-dev-threatmodeling`
taxonomy in
[`crypto-behavior-taxonomy.json`](../../output/src/main/resources/crypto-behavior-taxonomy.json).
The feature uses an experimental, tool-specific property rather than a standard
CycloneDX behavior field. The snapshot defines the available identifiers;
`CryptoBehavior` represents the subset the plugin emits.

## 2. Scope

The PR adds behavior inference and serialization in `output`, contextual evidence in
`engine` and `mapper`, Java authentication detection, and curated Java PRNG and
key-wrap detection. Crypto behavior mapping applies to algorithm nodes from any
supported language. Authentication detection is Java-only in this PR.

The summary describes the scanned application as a whole. It does not attribute
behaviors to individual assets or prove that a detected operation succeeds at runtime.

## 3. Evidence pipeline

Crypto findings follow the existing detection, translation, reorganization and
enrichment pipeline. Java auth rules produce an `AuthContext` finding;
`JavaAuthContextTranslator` translates it to
`ContextualEvidence(kind.name(), detectionLocation)`. This generic `INode` travels
through the same pipeline and retains its detection location, but never becomes a
cryptographic component in the CBOM.

The output subsystem has five responsibilities:

| Component | Responsibility |
|---|---|
| `CryptoBehaviorMapper` | Map each algorithm's operations and primitive kind to crypto behaviors. |
| `BehaviorCollector` | Observe algorithms and contextual evidence, retaining scan-wide sets. |
| `BehaviorSignals` | Snapshot the crypto-derived behaviors and observed auth kinds for inference. |
| `IBehaviorRule` | Contribute behaviors through the ordered registry: `CryptoBehaviorRule` passes crypto behaviors through; `AuthInterfaceRule` contributes auth behaviors. |
| `BehaviorMetadataWriter` | Serialize the inferred set into CycloneDX metadata. |

`CBOMOutputFile` observes contextual evidence during node dispatch and algorithms when
creating their components. The algorithm path also covers nested assets and protocol
cipher-suite constituents. At `getBom()`, the collector unions rule contributions
and the writer attaches the resulting property.

Evidence belongs to the output instance for one scan. Unknown contextual identifiers,
the `NONE` auth kind and unrelated nodes contribute no behaviors. Auth-only scans can
produce metadata without producing crypto components; their evidence nodes remain
part of aggregated scan results and statistics.

## 4. Output contract

Emit exactly one `cbomkit:crypto:behavior` property on `bom.metadata.component` when
the inferred set is non-empty. Its value contains full `security:cryptography:*`
identifiers, deduplicated, sorted lexicographically and joined with commas, without
spaces. The metadata component has type `application` and the fixed name
`application`, since the scanned project name is not supplied to the writer.

For example, an RSA key-wrap operation contributes:

```json
{
  "metadata": {
    "component": {
      "type": "application",
      "name": "application",
      "properties": [
        {
          "name": "cbomkit:crypto:behavior",
          "value": "security:cryptography:wrapsKey"
        }
      ]
    }
  }
}
```

This is a metadata excerpt. A complete CBOM also contains its detected crypto assets.
When inference produces no behaviors, omit the property and do not create a metadata
component solely for this feature. Auth evidence uses the same property and format as
crypto-derived behaviors.

## 5. Crypto behavior mapping

### 5.1 Operations

Evaluate every matching operation row and union its contributions. Operations are
represented by functionality children on an algorithm node. Behavior names below omit
the common `security:cryptography:` prefix.

| Detected operation | Behaviors |
|---|---|
| `Encrypt` | `encryptsData`, `ensuresConfidentiality` |
| `Decrypt` | `decryptsData`, `ensuresConfidentiality` |
| `Encapsulate` / `Decapsulate` on a cipher, including `PublicKeyEncryption` and `KeyWrap` | `wrapsKey` |
| `Encapsulate` / `Decapsulate` on `KeyEncapsulationMechanism` | `exchangesKey`, `ensuresConfidentiality` |
| `Sign` | `signsData`, `ensuresIntegrity`, `ensuresNonRepudiation` |
| `Verify` | `verifiesSignature`, `ensuresIntegrity` |
| `Digest` | `hashesData`, `ensuresIntegrity` |
| `Tag` | `ensuresIntegrity` |
| `Generate` on a PRNG | `generatesRandomValue` |
| `KeyGeneration` | `generatesKey` |
| `KeyDerivation` on a password-based KDF or PBE | `hashesPassword` |
| `KeyDerivation` otherwise | `generatesKey` |

JCA `Cipher.wrap`, `Cipher.unwrap`, `WRAP_MODE` and `UNWRAP_MODE` supply
`Encapsulate` / `Decapsulate` evidence. RSA wrapping and unwrapping must contribute
`wrapsKey` without generic encryption/decryption fallback behaviors. KEM operations
remain distinct and contribute `exchangesKey`.

### 5.2 Primitive fallback

When no operation row contributes, use the first matching primitive row. More specific
kinds precede generic ones. Unsupported kinds and non-algorithm nodes contribute
nothing.

| Primitive kind | Behaviors |
|---|---|
| `AuthenticatedEncryption` | `encryptsData`, `decryptsData`, `ensuresConfidentiality`, `ensuresIntegrity` |
| `BlockCipher`, `StreamCipher`, `Cipher`, `PublicKeyEncryption` | `encryptsData`, `decryptsData`, `ensuresConfidentiality` |
| `Signature`, `ProbabilisticSignatureScheme` | `signsData`, `verifiesSignature`, `ensuresIntegrity`, `ensuresNonRepudiation` |
| `MessageDigest` | `hashesData`, `ensuresIntegrity` |
| `Mac` | `ensuresIntegrity` |
| `KeyEncapsulationMechanism` | `exchangesKey`, `ensuresConfidentiality` |
| `KeyWrap` | `wrapsKey` |
| `KeyAgreement` | `exchangesKey` |
| `PasswordBasedKeyDerivationFunction`, `PasswordBasedEncryption` | `hashesPassword` |
| `KeyDerivationFunction` | `generatesKey` |
| `PseudorandomNumberGenerator` | `generatesRandomValue` |

Java PRNG detection covers the existing seed calls plus no-argument `SecureRandom`
construction, `getInstance(String)` and `getInstanceStrong()`. Recognized native/DRBG
names map to a generic `PRNG` asset; a default constructor does not identify the
platform's actual algorithm. This intentionally broad detection can add PRNG components
and `generatesRandomValue` to scans that previously omitted them.

## 6. Authentication behaviors

Crypto mapping never emits `authenticates`: a MAC or signature alone does not establish
application authentication. Auth behaviors require a recognized contextual kind.
Multiple kinds union their contributions; no additional crypto evidence is required.

| Auth kind | Java detection anchors | Behaviors |
|---|---|---|
| `JWT` | jjwt signed-claims parsing; Nimbus signed JWT/JWS verification; Auth0 JWT verification | `authenticates`, `validatesToken` |
| `OAUTH` | Spring JWT decoding and opaque-token introspection; Nimbus ID-token validation | `authenticates`, `validatesToken` |
| `SAML` | OpenSAML signature/profile validation; Spring SAML2 authentication | `authenticates`, `validatesToken` |
| `PRINCIPAL` | Servlet/JAX-RS `getUserPrincipal` in both namespaces; Spring `Authentication.getPrincipal` | `authenticates`, `usesIdentity` |
| `MTLS` | `X509TrustManager.checkClientTrusted`; SSL-session peer principal/certificate access; Spring X.509 filter construction | `authenticates`, `usesIdentity` |
| `API_KEY` | pac4j header/parameter client construction; Spring request-header authentication filter construction | `authenticates` |
| `NONE` or unknown identifier | No contribution | None |

Token rules match verification or validation calls rather than parser construction.
Principal and mTLS rules use identity-access or framework anchors; API-key coverage
uses framework constructors. These are static evidence heuristics. Generic header
reads, imports and dependency presence do not supply auth evidence.

Auth rule sets use `DetectionRuleSet` and the shared `RuleSets.rulesOf(...)` registry,
so rule lists are cached consistently with the existing Java detection graph. Pinned
library JARs provide semantic resolution in tests and are test dependencies.

## 7. Limits and deferred work

Primitive fallback describes plausible capabilities, while explicit operation evidence
provides greater specificity. Security-goal behaviors do not certify correct or secure
use. The taxonomy has no dedicated MAC-computation or generic key-derivation verb, so
MACs contribute integrity and generic KDFs approximate derivation as `generatesKey`.

Deferred work includes per-asset attribution, confidence scoring, auth detection in
other languages, annotation/import/dependency evidence, key-store lifecycle behaviors,
certificate/PKI and code-signing behaviors, and data-at-rest/in-transit distinctions.
First-class CycloneDX behavior fields can replace the experimental property when an
appropriate standard format is adopted.

## 8. Validation

Tests cover operation mapping and ordered fallback, including AES and RSA wrapping
and unwrapping, distinct KEM behavior, MAC-only auth suppression, every auth kind,
unknown evidence and empty input. Exact RSA assertions exclude the erroneous generic
encryption/decryption behaviors. Taxonomy tests require every emitted enum identifier
to exist in the bundled JSON snapshot.

Each supported auth library has a separate detection test and source fixture, with
exact call-location assertions and examples that configure or use its authentication
API. Negative examples cover parser construction, unverified token decoding and plain
header reads. Other detection fixtures cover SecureRandom and key wrapping. Pipeline and
CBOM tests verify contextual evidence survives translation/enrichment, creates no
crypto component, and contributes to sorted, deduplicated metadata. They also cover
empty output, auth-only evidence and algorithms nested in protocol cipher suites.

Run `mvn -pl java,output -am test spotless:check checkstyle:check` for the affected
pipeline, and `mvn clean package` for the full build.
