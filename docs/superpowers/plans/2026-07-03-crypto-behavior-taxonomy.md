# Crypto Behavior Taxonomy (Part A: Mapping + Output) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Attach a CycloneDX 2.0-dev cryptographic-behavior summary of the scanned software to the generated CBOM as a single property on `metadata.component`.

**Architecture:** A new `behavior/` sub-package in the `output` module holds a local taxonomy snapshot (`crypto-behavior-taxonomy.json`), a `CryptoBehavior` enum of the identifiers we emit, and a pure `CryptoBehaviorMapper` that turns each detected asset (`INode`) into a set of behaviors. `CBOMOutputFile` accumulates behaviors across the whole scan while it walks the node tree and, in `getBom()`, emits their sorted union as one `cbomkit:crypto:behavior` property on a freshly-created `metadata.component`.

**Tech Stack:** Java 17, Maven (multi-module), JUnit 5 + AssertJ, cyclonedx-core-java (`org.cyclonedx.model.*`), Jackson (`com.fasterxml.jackson.databind`, transitive via cyclonedx) for reading the JSON resource.

**Spec:** `docs/superpowers/specs/2026-07-03-crypto-behavior-taxonomy-design.md`

**Scope note:** This is **Part A** of a two-plan split. The curated *new detection* work (`generatesRandomValue` wiring, `Cipher.unwrap` rule) is **Part B**, a separate follow-up plan. Part A already yields `wrapsKey` and `exchangesKey` because `WRAP_MODE`→`Encapsulate`-on-a-Cipher and KEM `Encapsulate` already flow through the existing pipeline.

## Global Constraints

- **Java 17.** No newer language features.
- **License header:** every new `.java` file needs the Apache 2.0 header. It is applied automatically by `mvn spotless:apply` — run it before every commit; do not hand-write the header.
- **Formatting:** Google Java Format (AOSP style) via Spotless. Run `mvn spotless:apply` before each commit.
- **Checkstyle:** no unused imports; `@Override` required on interface/inherited method implementations.
- **Module build/test command:** `mvn test -pl output -am` (the `-am` builds the `mapper`/`engine` dependencies first).
- **Property name (verbatim):** `cbomkit:crypto:behavior`
- **Behavior identifier format (verbatim):** `security:cryptography:<leafName>`
- **Branch:** `feature/crypto-behavior-taxonomy`

---

### Task 1: Local taxonomy snapshot + `CryptoBehavior` enum + sync test

**Files:**
- Create: `output/src/main/resources/crypto-behavior-taxonomy.json`
- Create: `output/src/main/java/com/ibm/output/cyclondx/behavior/CryptoBehavior.java`
- Test: `output/src/test/java/com/ibm/output/cyclonedx/behavior/CryptoBehaviorTaxonomyTest.java`

**Interfaces:**
- Produces:
  - `enum CryptoBehavior` with values `ENCRYPTS_DATA, DECRYPTS_DATA, SIGNS_DATA, VERIFIES_SIGNATURE, HASHES_DATA, HASHES_PASSWORD, GENERATES_KEY, GENERATES_RANDOM_VALUE, EXCHANGES_KEY, WRAPS_KEY, AUTHENTICATES, ENSURES_CONFIDENTIALITY, ENSURES_INTEGRITY, ENSURES_NON_REPUDIATION`.
  - `String CryptoBehavior.fullId()` → `"security:cryptography:" + leafName` (e.g. `security:cryptography:encryptsData`).
  - Resource `crypto-behavior-taxonomy.json`: a JSON array of `{ "identifier": String, "name": String, "category": "security:cryptography" }`.

- [ ] **Step 1: Write the failing sync test**

Create `output/src/test/java/com/ibm/output/cyclonedx/behavior/CryptoBehaviorTaxonomyTest.java`:

```java
package com.ibm.output.cyclonedx.behavior;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ibm.output.cyclondx.behavior.CryptoBehavior;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class CryptoBehaviorTaxonomyTest {

    private Set<String> taxonomyIdentifiers() throws Exception {
        final Set<String> ids = new HashSet<>();
        try (InputStream in =
                getClass().getClassLoader().getResourceAsStream("crypto-behavior-taxonomy.json")) {
            assertThat(in).as("crypto-behavior-taxonomy.json must be on the classpath").isNotNull();
            final JsonNode root = new ObjectMapper().readTree(in);
            assertThat(root.isArray()).isTrue();
            root.forEach(node -> ids.add(node.get("identifier").asText()));
        }
        return ids;
    }

    @Test
    void everyEmittedBehaviorExistsInTheTaxonomySnapshot() throws Exception {
        final Set<String> ids = taxonomyIdentifiers();
        for (CryptoBehavior behavior : CryptoBehavior.values()) {
            assertThat(ids)
                    .as("taxonomy snapshot is missing %s", behavior.fullId())
                    .contains(behavior.fullId());
        }
    }

    @Test
    void fullIdIsNamespaced() {
        assertThat(CryptoBehavior.ENCRYPTS_DATA.fullId())
                .isEqualTo("security:cryptography:encryptsData");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mvn test -pl output -am -Dtest=CryptoBehaviorTaxonomyTest`
Expected: FAIL — compilation error, `package com.ibm.output.cyclondx.behavior does not exist` (the enum and resource do not exist yet).

- [ ] **Step 3: Create the `CryptoBehavior` enum**

Create `output/src/main/java/com/ibm/output/cyclondx/behavior/CryptoBehavior.java` (Spotless will add the license header):

```java
package com.ibm.output.cyclondx.behavior;

import javax.annotation.Nonnull;

/**
 * Experimental crypto behaviors from the CycloneDX 2.0-dev threat-modeling taxonomy
 * ({@code security:cryptography:*}). Only the subset this plugin can emit is represented here; the
 * full draft list is mirrored in {@code crypto-behavior-taxonomy.json}.
 */
public enum CryptoBehavior {
    ENCRYPTS_DATA("encryptsData"),
    DECRYPTS_DATA("decryptsData"),
    SIGNS_DATA("signsData"),
    VERIFIES_SIGNATURE("verifiesSignature"),
    HASHES_DATA("hashesData"),
    HASHES_PASSWORD("hashesPassword"),
    GENERATES_KEY("generatesKey"),
    GENERATES_RANDOM_VALUE("generatesRandomValue"),
    EXCHANGES_KEY("exchangesKey"),
    WRAPS_KEY("wrapsKey"),
    AUTHENTICATES("authenticates"),
    ENSURES_CONFIDENTIALITY("ensuresConfidentiality"),
    ENSURES_INTEGRITY("ensuresIntegrity"),
    ENSURES_NON_REPUDIATION("ensuresNonRepudiation");

    private static final String NAMESPACE = "security:cryptography:";

    @Nonnull private final String leafName;

    CryptoBehavior(@Nonnull String leafName) {
        this.leafName = leafName;
    }

    @Nonnull
    public String fullId() {
        return NAMESPACE + this.leafName;
    }
}
```

- [ ] **Step 4: Create the taxonomy JSON snapshot**

Create `output/src/main/resources/crypto-behavior-taxonomy.json`. This is a local, verbatim snapshot of the crypto behavior identifiers from the CycloneDX `2.0-dev-threatmodeling` branch (`schema/behavior-taxonomy.schema.json`, the `security:cryptography:*` enum). It is intentionally the full draft list, not just the emitted subset:

```json
[
  { "identifier": "security:cryptography:authenticates", "name": "authenticates", "category": "security:cryptography" },
  { "identifier": "security:cryptography:checksRevocation", "name": "checksRevocation", "category": "security:cryptography" },
  { "identifier": "security:cryptography:decryptsData", "name": "decryptsData", "category": "security:cryptography" },
  { "identifier": "security:cryptography:decryptsDataAtRest", "name": "decryptsDataAtRest", "category": "security:cryptography" },
  { "identifier": "security:cryptography:decryptsDataInTransit", "name": "decryptsDataInTransit", "category": "security:cryptography" },
  { "identifier": "security:cryptography:decryptsDisk", "name": "decryptsDisk", "category": "security:cryptography" },
  { "identifier": "security:cryptography:decryptsSecret", "name": "decryptsSecret", "category": "security:cryptography" },
  { "identifier": "security:cryptography:destroysKey", "name": "destroysKey", "category": "security:cryptography" },
  { "identifier": "security:cryptography:encryptsData", "name": "encryptsData", "category": "security:cryptography" },
  { "identifier": "security:cryptography:encryptsDataAtRest", "name": "encryptsDataAtRest", "category": "security:cryptography" },
  { "identifier": "security:cryptography:encryptsDataInTransit", "name": "encryptsDataInTransit", "category": "security:cryptography" },
  { "identifier": "security:cryptography:encryptsDisk", "name": "encryptsDisk", "category": "security:cryptography" },
  { "identifier": "security:cryptography:encryptsSecret", "name": "encryptsSecret", "category": "security:cryptography" },
  { "identifier": "security:cryptography:ensuresAccountability", "name": "ensuresAccountability", "category": "security:cryptography" },
  { "identifier": "security:cryptography:ensuresConfidentiality", "name": "ensuresConfidentiality", "category": "security:cryptography" },
  { "identifier": "security:cryptography:ensuresIntegrity", "name": "ensuresIntegrity", "category": "security:cryptography" },
  { "identifier": "security:cryptography:ensuresNonRepudiation", "name": "ensuresNonRepudiation", "category": "security:cryptography" },
  { "identifier": "security:cryptography:exchangesKey", "name": "exchangesKey", "category": "security:cryptography" },
  { "identifier": "security:cryptography:generatesKey", "name": "generatesKey", "category": "security:cryptography" },
  { "identifier": "security:cryptography:generatesRandomValue", "name": "generatesRandomValue", "category": "security:cryptography" },
  { "identifier": "security:cryptography:hashesData", "name": "hashesData", "category": "security:cryptography" },
  { "identifier": "security:cryptography:hashesPassword", "name": "hashesPassword", "category": "security:cryptography" },
  { "identifier": "security:cryptography:identifies", "name": "identifies", "category": "security:cryptography" },
  { "identifier": "security:cryptography:issuesCertificate", "name": "issuesCertificate", "category": "security:cryptography" },
  { "identifier": "security:cryptography:preservesPrivacy", "name": "preservesPrivacy", "category": "security:cryptography" },
  { "identifier": "security:cryptography:presentsClientCertificate", "name": "presentsClientCertificate", "category": "security:cryptography" },
  { "identifier": "security:cryptography:presentsServerCertificate", "name": "presentsServerCertificate", "category": "security:cryptography" },
  { "identifier": "security:cryptography:retrievesKey", "name": "retrievesKey", "category": "security:cryptography" },
  { "identifier": "security:cryptography:revokesCertificate", "name": "revokesCertificate", "category": "security:cryptography" },
  { "identifier": "security:cryptography:rotatesKey", "name": "rotatesKey", "category": "security:cryptography" },
  { "identifier": "security:cryptography:signsCode", "name": "signsCode", "category": "security:cryptography" },
  { "identifier": "security:cryptography:signsData", "name": "signsData", "category": "security:cryptography" },
  { "identifier": "security:cryptography:signsDocument", "name": "signsDocument", "category": "security:cryptography" },
  { "identifier": "security:cryptography:storesKey", "name": "storesKey", "category": "security:cryptography" },
  { "identifier": "security:cryptography:usesIdentity", "name": "usesIdentity", "category": "security:cryptography" },
  { "identifier": "security:cryptography:validatesCertificate", "name": "validatesCertificate", "category": "security:cryptography" },
  { "identifier": "security:cryptography:validatesToken", "name": "validatesToken", "category": "security:cryptography" },
  { "identifier": "security:cryptography:verifiesCodeSignature", "name": "verifiesCodeSignature", "category": "security:cryptography" },
  { "identifier": "security:cryptography:verifiesDataSignature", "name": "verifiesDataSignature", "category": "security:cryptography" },
  { "identifier": "security:cryptography:verifiesDocumentSignature", "name": "verifiesDocumentSignature", "category": "security:cryptography" },
  { "identifier": "security:cryptography:verifiesHash", "name": "verifiesHash", "category": "security:cryptography" },
  { "identifier": "security:cryptography:verifiesSignature", "name": "verifiesSignature", "category": "security:cryptography" },
  { "identifier": "security:cryptography:wrapsKey", "name": "wrapsKey", "category": "security:cryptography" }
]
```

- [ ] **Step 5: Format, then run the test to verify it passes**

Run: `mvn spotless:apply -pl output && mvn test -pl output -am -Dtest=CryptoBehaviorTaxonomyTest`
Expected: PASS — both tests green.

- [ ] **Step 6: Commit**

```bash
git add output/src/main/resources/crypto-behavior-taxonomy.json \
        output/src/main/java/com/ibm/output/cyclondx/behavior/CryptoBehavior.java \
        output/src/test/java/com/ibm/output/cyclonedx/behavior/CryptoBehaviorTaxonomyTest.java
git commit -m "feat(output): add crypto behavior taxonomy snapshot and enum"
```

---

### Task 2: `CryptoBehaviorMapper` (asset → behaviors)

**Files:**
- Create: `output/src/main/java/com/ibm/output/cyclondx/behavior/CryptoBehaviorMapper.java`
- Test: `output/src/test/java/com/ibm/output/cyclonedx/behavior/CryptoBehaviorMapperTest.java`

**Interfaces:**
- Consumes: `CryptoBehavior` (Task 1); `com.ibm.mapper.model.INode`.
- Produces:
  - `public static final String CryptoBehaviorMapper.BEHAVIOR_PROPERTY_NAME = "cbomkit:crypto:behavior"`.
  - `Set<CryptoBehavior> CryptoBehaviorMapper.map(INode node)` — total (never throws); returns an empty set for non-`Algorithm` nodes or unmappable assets.

**Mapping rules (from spec §5):** operational pass first (reads `Functionality` children + exact primitive kind); if it produces nothing, a primitive-kind fallback runs. `is()` matches the *exact* kind, so every relevant concrete kind is enumerated explicitly.

- [ ] **Step 1: Write the failing mapper tests**

Create `output/src/test/java/com/ibm/output/cyclonedx/behavior/CryptoBehaviorMapperTest.java`:

```java
package com.ibm.output.cyclonedx.behavior;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Collections;
import org.junit.jupiter.api.Test;

class CryptoBehaviorMapperTest {

    private final IBundle bundle = () -> "Test";
    private final DetectionLocation loc =
            new DetectionLocation("test.java", 1, 1, Collections.emptyList(), bundle);
    private final CryptoBehaviorMapper mapper = new CryptoBehaviorMapper();

    @Test
    void encryptOperationYieldsEncryptsDataAndConfidentiality() {
        final AES aes = new AES(loc);
        aes.put(new Encrypt(loc));
        assertThat(mapper.map(aes))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.ENCRYPTS_DATA, CryptoBehavior.ENSURES_CONFIDENTIALITY);
    }

    @Test
    void signOperationYieldsSignsDataIntegrityAndNonRepudiation() {
        final RSA rsa = new RSA(Signature.class, loc);
        rsa.put(new Sign(loc));
        assertThat(mapper.map(rsa))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.SIGNS_DATA,
                        CryptoBehavior.ENSURES_INTEGRITY,
                        CryptoBehavior.ENSURES_NON_REPUDIATION);
    }

    @Test
    void encapsulateOnCipherYieldsWrapsKey() {
        final AES aes = new AES(loc); // kind BlockCipher
        aes.put(new Encapsulate(loc));
        assertThat(mapper.map(aes)).containsExactly(CryptoBehavior.WRAPS_KEY);
    }

    @Test
    void encapsulateOnKemYieldsExchangesKey() {
        final Algorithm kem = new Algorithm("ML-KEM", KeyEncapsulationMechanism.class, loc);
        kem.put(new Encapsulate(loc));
        assertThat(mapper.map(kem))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.EXCHANGES_KEY, CryptoBehavior.ENSURES_CONFIDENTIALITY);
    }

    @Test
    void generateOnPrngYieldsGeneratesRandomValue() {
        final Algorithm drbg =
                new Algorithm("TestDRBG", PseudorandomNumberGenerator.class, loc);
        drbg.put(new Generate(loc));
        assertThat(mapper.map(drbg)).containsExactly(CryptoBehavior.GENERATES_RANDOM_VALUE);
    }

    @Test
    void keyDerivationOnPasswordBasedKdfYieldsHashesPassword() {
        final PBKDF2 pbkdf2 = new PBKDF2(loc);
        pbkdf2.put(new KeyDerivation(loc));
        assertThat(mapper.map(pbkdf2)).containsExactly(CryptoBehavior.HASHES_PASSWORD);
    }

    @Test
    void bareMessageDigestFallsBackToHashesDataAndIntegrity() {
        final SHA2 sha256 = new SHA2(256, loc); // no functionality child
        assertThat(mapper.map(sha256))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.HASHES_DATA, CryptoBehavior.ENSURES_INTEGRITY);
    }

    @Test
    void bareMacFallsBackToAuthenticatesAndIntegrity() {
        final HMAC hmac = new HMAC(loc);
        assertThat(mapper.map(hmac))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.AUTHENTICATES, CryptoBehavior.ENSURES_INTEGRITY);
    }

    @Test
    void bareKeyAgreementFallsBackToExchangesKey() {
        final ECDH ecdh = new ECDH(loc);
        assertThat(mapper.map(ecdh)).containsExactly(CryptoBehavior.EXCHANGES_KEY);
    }

    @Test
    void bareBlockCipherFallsBackToEncryptDecryptConfidentiality() {
        final AES aes = new AES(loc);
        assertThat(mapper.map(aes))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.ENCRYPTS_DATA,
                        CryptoBehavior.DECRYPTS_DATA,
                        CryptoBehavior.ENSURES_CONFIDENTIALITY);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `mvn test -pl output -am -Dtest=CryptoBehaviorMapperTest`
Expected: FAIL — compilation error, `CryptoBehaviorMapper` does not exist.

- [ ] **Step 3: Implement `CryptoBehaviorMapper`**

Create `output/src/main/java/com/ibm/output/cyclondx/behavior/CryptoBehaviorMapper.java`:

```java
package com.ibm.output.cyclondx.behavior;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.StreamCipher;
import com.ibm.mapper.model.functionality.Decapsulate;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Tag;
import com.ibm.mapper.model.functionality.Verify;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Derives {@link CryptoBehavior}s for a detected cryptographic asset. Operation-first: reads the
 * asset's {@code Functionality} children and its exact primitive kind. If no operation is present,
 * a primitive-kind fallback infers the plausible behaviors. Never throws; unmappable input yields
 * an empty set. See spec §5 for the mapping tables and known taxonomy gaps.
 */
public final class CryptoBehaviorMapper {

    public static final String BEHAVIOR_PROPERTY_NAME = "cbomkit:crypto:behavior";

    @Nonnull
    public Set<CryptoBehavior> map(@Nonnull INode node) {
        final Set<CryptoBehavior> behaviors = EnumSet.noneOf(CryptoBehavior.class);
        if (!(node instanceof Algorithm)) {
            return behaviors;
        }

        final Map<Class<? extends INode>, INode> children = node.getChildren();
        final boolean isCipher =
                node.is(BlockCipher.class)
                        || node.is(StreamCipher.class)
                        || node.is(Cipher.class)
                        || node.is(AuthenticatedEncryption.class);
        final boolean isKem = node.is(KeyEncapsulationMechanism.class);
        final boolean isPrng = node.is(PseudorandomNumberGenerator.class);
        final boolean isPasswordKdf =
                node.is(PasswordBasedKeyDerivationFunction.class)
                        || node.is(PasswordBasedEncryption.class);

        // --- Operational pass (reads detected Functionality children) ---
        if (children.containsKey(Encrypt.class)) {
            behaviors.add(CryptoBehavior.ENCRYPTS_DATA);
            behaviors.add(CryptoBehavior.ENSURES_CONFIDENTIALITY);
        }
        if (children.containsKey(Decrypt.class)) {
            behaviors.add(CryptoBehavior.DECRYPTS_DATA);
            behaviors.add(CryptoBehavior.ENSURES_CONFIDENTIALITY);
        }
        if (children.containsKey(Encapsulate.class) || children.containsKey(Decapsulate.class)) {
            if (isKem) {
                behaviors.add(CryptoBehavior.EXCHANGES_KEY);
                behaviors.add(CryptoBehavior.ENSURES_CONFIDENTIALITY);
            } else if (isCipher) {
                // JCA WRAP_MODE/UNWRAP_MODE and Cipher.wrap surface as (De)Encapsulate on a Cipher.
                behaviors.add(CryptoBehavior.WRAPS_KEY);
            }
        }
        if (children.containsKey(Sign.class)) {
            behaviors.add(CryptoBehavior.SIGNS_DATA);
            behaviors.add(CryptoBehavior.ENSURES_INTEGRITY);
            behaviors.add(CryptoBehavior.ENSURES_NON_REPUDIATION);
        }
        if (children.containsKey(Verify.class)) {
            behaviors.add(CryptoBehavior.VERIFIES_SIGNATURE);
            behaviors.add(CryptoBehavior.ENSURES_INTEGRITY);
        }
        if (children.containsKey(Digest.class)) {
            behaviors.add(CryptoBehavior.HASHES_DATA);
            behaviors.add(CryptoBehavior.ENSURES_INTEGRITY);
        }
        if (children.containsKey(Tag.class)) {
            // No operational "computesMac" verb in the taxonomy; use goal-level behaviors (spec §5.1).
            behaviors.add(CryptoBehavior.AUTHENTICATES);
            behaviors.add(CryptoBehavior.ENSURES_INTEGRITY);
        }
        if (children.containsKey(Generate.class) && isPrng) {
            behaviors.add(CryptoBehavior.GENERATES_RANDOM_VALUE);
        }
        if (children.containsKey(KeyGeneration.class)) {
            behaviors.add(CryptoBehavior.GENERATES_KEY);
        }
        if (children.containsKey(KeyDerivation.class)) {
            // Generic KDF has no "deriveKey" value; approximated as generatesKey (spec §5.1).
            behaviors.add(isPasswordKdf ? CryptoBehavior.HASHES_PASSWORD : CryptoBehavior.GENERATES_KEY);
        }

        // --- Primitive-kind fallback (only when no operation was detected) ---
        if (behaviors.isEmpty()) {
            applyPrimitiveFallback(node, behaviors);
        }
        return behaviors;
    }

    private void applyPrimitiveFallback(
            @Nonnull INode node, @Nonnull Set<CryptoBehavior> behaviors) {
        if (node.is(AuthenticatedEncryption.class)) {
            behaviors.add(CryptoBehavior.ENCRYPTS_DATA);
            behaviors.add(CryptoBehavior.DECRYPTS_DATA);
            behaviors.add(CryptoBehavior.ENSURES_CONFIDENTIALITY);
            behaviors.add(CryptoBehavior.ENSURES_INTEGRITY);
        } else if (node.is(BlockCipher.class)
                || node.is(StreamCipher.class)
                || node.is(Cipher.class)
                || node.is(PublicKeyEncryption.class)) {
            behaviors.add(CryptoBehavior.ENCRYPTS_DATA);
            behaviors.add(CryptoBehavior.DECRYPTS_DATA);
            behaviors.add(CryptoBehavior.ENSURES_CONFIDENTIALITY);
        } else if (node.is(Signature.class) || node.is(ProbabilisticSignatureScheme.class)) {
            behaviors.add(CryptoBehavior.SIGNS_DATA);
            behaviors.add(CryptoBehavior.VERIFIES_SIGNATURE);
            behaviors.add(CryptoBehavior.ENSURES_INTEGRITY);
            behaviors.add(CryptoBehavior.ENSURES_NON_REPUDIATION);
        } else if (node.is(MessageDigest.class)) {
            behaviors.add(CryptoBehavior.HASHES_DATA);
            behaviors.add(CryptoBehavior.ENSURES_INTEGRITY);
        } else if (node.is(Mac.class)) {
            behaviors.add(CryptoBehavior.AUTHENTICATES);
            behaviors.add(CryptoBehavior.ENSURES_INTEGRITY);
        } else if (node.is(KeyEncapsulationMechanism.class)) {
            behaviors.add(CryptoBehavior.EXCHANGES_KEY);
            behaviors.add(CryptoBehavior.ENSURES_CONFIDENTIALITY);
        } else if (node.is(KeyAgreement.class)) {
            behaviors.add(CryptoBehavior.EXCHANGES_KEY);
        } else if (node.is(PasswordBasedKeyDerivationFunction.class)
                || node.is(PasswordBasedEncryption.class)) {
            behaviors.add(CryptoBehavior.HASHES_PASSWORD);
        } else if (node.is(KeyDerivationFunction.class)) {
            behaviors.add(CryptoBehavior.GENERATES_KEY);
        } else if (node.is(PseudorandomNumberGenerator.class)) {
            behaviors.add(CryptoBehavior.GENERATES_RANDOM_VALUE);
        }
    }
}
```

Note on ordering: `AuthenticatedEncryption` is checked before the generic cipher branch because a GCM-mode AES has kind `AuthenticatedEncryption` (the enricher re-types it) and must get the integrity behavior too.

- [ ] **Step 4: Format, then run the tests to verify they pass**

Run: `mvn spotless:apply -pl output && mvn test -pl output -am -Dtest=CryptoBehaviorMapperTest`
Expected: PASS — all 10 tests green.

- [ ] **Step 5: Commit**

```bash
git add output/src/main/java/com/ibm/output/cyclondx/behavior/CryptoBehaviorMapper.java \
        output/src/test/java/com/ibm/output/cyclonedx/behavior/CryptoBehaviorMapperTest.java
git commit -m "feat(output): map detected assets to crypto behaviors"
```

---

### Task 3: Emit aggregated behavior property on `metadata.component`

**Files:**
- Modify: `output/src/main/java/com/ibm/output/cyclondx/CBOMOutputFile.java`
- Test: `output/src/test/java/com/ibm/output/cyclonedx/CryptoBehaviorMetadataTest.java`

**Interfaces:**
- Consumes: `CryptoBehaviorMapper` (`map(INode)`, `BEHAVIOR_PROPERTY_NAME`) and `CryptoBehavior` (`fullId()`) from Tasks 1–2.
- Produces: a `Bom` whose `metadata.component` (type `APPLICATION`, name `"application"`) carries at most one `Property` named `cbomkit:crypto:behavior` whose value is the sorted, comma-joined union of all detected assets' behavior `fullId()`s. No `metadata.component` is set when the scan produced no behaviors.

- [ ] **Step 1: Write the failing integration test**

Create `output/src/test/java/com/ibm/output/cyclonedx/CryptoBehaviorMetadataTest.java`:

```java
package com.ibm.output.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.output.cyclondx.CBOMOutputFile;
import java.util.Collections;
import java.util.List;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Property;
import org.junit.jupiter.api.Test;

class CryptoBehaviorMetadataTest {

    private final IBundle bundle = () -> "Test";
    private final DetectionLocation loc =
            new DetectionLocation("test.java", 1, 1, Collections.emptyList(), bundle);

    private Bom bomOf(List<INode> nodes) {
        final CBOMOutputFile outputFile = new CBOMOutputFile();
        nodes.forEach(node -> outputFile.add(List.of(node)));
        return outputFile.getBom();
    }

    @Test
    void aggregatesBehaviorsOfWholeScanOntoMetadataComponent() {
        final AES aes = new AES(loc);
        aes.put(new Encrypt(loc));
        final Bom bom = bomOf(List.of(aes, new SHA2(256, loc), new HMAC(loc)));

        final Component metaComponent = bom.getMetadata().getComponent();
        assertThat(metaComponent).isNotNull();
        assertThat(metaComponent.getType()).isEqualTo(Component.Type.APPLICATION);

        assertThat(metaComponent.getProperties()).hasSize(1);
        final Property property = metaComponent.getProperties().get(0);
        assertThat(property.getName()).isEqualTo("cbomkit:crypto:behavior");
        assertThat(property.getValue())
                .isEqualTo(
                        "security:cryptography:authenticates,"
                                + "security:cryptography:encryptsData,"
                                + "security:cryptography:ensuresConfidentiality,"
                                + "security:cryptography:ensuresIntegrity,"
                                + "security:cryptography:hashesData");
    }

    @Test
    void noMetadataComponentWhenNoBehaviorsDetected() {
        // A lone functionality node is not an Algorithm asset, so the mapper returns no behaviors
        // and getBom() must not create a metadata.component (spec §6).
        final Bom bom = bomOf(List.of(new Encrypt(loc)));
        assertThat(bom.getMetadata().getComponent()).isNull();
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mvn test -pl output -am -Dtest=CryptoBehaviorMetadataTest`
Expected: FAIL — `bom.getMetadata().getComponent()` is `null` (no metadata.component is created today), so the first assertion fails.

- [ ] **Step 3: Add the accumulator field and mapper to `CBOMOutputFile`**

In `output/src/main/java/com/ibm/output/cyclondx/CBOMOutputFile.java`, add imports (keep alphabetical order within the existing import blocks):

```java
import com.ibm.output.cyclondx.behavior.CryptoBehavior;
import com.ibm.output.cyclondx.behavior.CryptoBehaviorMapper;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.cyclonedx.model.Property;
```

Add two fields next to the existing `components`/`dependencies` fields (around line 78) and a name constant:

```java
    @Nonnull private final Map<String, Component> components;
    @Nonnull private final Map<String, Dependency> dependencies;
    @Nonnull private final Set<CryptoBehavior> aggregatedBehaviors = EnumSet.noneOf(CryptoBehavior.class);
    @Nonnull private final CryptoBehaviorMapper behaviorMapper = new CryptoBehaviorMapper();

    private static final String METADATA_COMPONENT_NAME = "application";
```

- [ ] **Step 4: Accumulate behaviors during tree traversal**

In the private `add(@Nullable final String parentBomRef, @Nonnull List<INode> nodes)` method, make the accumulation the first action for each node inside the `forEach` lambda (the mapper self-guards on `Algorithm`, so calling it on every node is safe and DRY):

```java
    private void add(@Nullable final String parentBomRef, @Nonnull List<INode> nodes) {
        nodes.forEach(
                node -> {
                    this.aggregatedBehaviors.addAll(this.behaviorMapper.map(node));
                    // switch for asset
                    if (node instanceof Algorithm algorithm) {
                        createAlgorithmComponent(parentBomRef, algorithm);
                    } else if (node instanceof Key key) {
                        createKeyComponent(parentBomRef, key);
                    } else if (node instanceof Protocol protocol) {
                        createProtocolComponent(parentBomRef, protocol);
                    } else if (node instanceof CipherSuite cipherSuite) {
                        createCipherSuiteComponent(parentBomRef, cipherSuite);
                    } else if (node instanceof SaltLength
                            || node instanceof PasswordLength
                            || node instanceof InitializationVectorLength
                            || node instanceof NonceLength) {
                        final IProperty property = (IProperty) node;
                        createRelatedCryptoMaterialComponent(parentBomRef, property);
                    } else if (node.hasChildren()) {
                        add(parentBomRef, node.getChildren().values().stream().toList());
                    }
                });
    }
```

- [ ] **Step 5: Emit the property on `metadata.component` in `getBom()`**

In `getBom()`, immediately before `bom.setMetadata(metadata);`, insert the metadata-component construction:

```java
        metadata.setToolChoice(scannerInfo);

        // Experimental: attach the scan-wide crypto behavior summary to metadata.component.
        if (!this.aggregatedBehaviors.isEmpty()) {
            final Component softwareComponent = new Component();
            softwareComponent.setType(Component.Type.APPLICATION);
            softwareComponent.setName(METADATA_COMPONENT_NAME);
            final String value =
                    this.aggregatedBehaviors.stream()
                            .map(CryptoBehavior::fullId)
                            .sorted()
                            .collect(Collectors.joining(","));
            final Property behaviorProperty = new Property();
            behaviorProperty.setName(CryptoBehaviorMapper.BEHAVIOR_PROPERTY_NAME);
            behaviorProperty.setValue(value);
            softwareComponent.setProperties(List.of(behaviorProperty));
            metadata.setComponent(softwareComponent);
        }

        bom.setMetadata(metadata);
```

- [ ] **Step 6: Format, then run the new test to verify it passes**

Run: `mvn spotless:apply -pl output && mvn test -pl output -am -Dtest=CryptoBehaviorMetadataTest`
Expected: PASS — both tests green.

- [ ] **Step 7: Run the full output module test suite (regression check)**

Run: `mvn test -pl output -am`
Expected: PASS — all pre-existing output tests still green (adding `metadata.component` does not affect the `components`/`dependencies` assertions they make).

- [ ] **Step 8: Commit**

```bash
git add output/src/main/java/com/ibm/output/cyclondx/CBOMOutputFile.java \
        output/src/test/java/com/ibm/output/cyclonedx/CryptoBehaviorMetadataTest.java
git commit -m "feat(output): emit aggregated crypto behavior on metadata.component"
```

---

## Verification (end of plan)

- [ ] `mvn test -pl output -am` — all output tests pass.
- [ ] `mvn spotless:check -pl output` — formatting clean.
- [ ] `mvn checkstyle:check -pl output` — no violations (no unused imports).
- [ ] Manually confirm a generated CBOM (or the integration-test BOM print) contains, under `metadata.component.properties`, one entry `{"name":"cbomkit:crypto:behavior","value":"security:cryptography:..."}`.

## Spec coverage map

| Spec section | Task |
|---|---|
| §4.1 taxonomy JSON snapshot | Task 1 |
| §4.2 `CryptoBehavior` enum + sync test | Task 1 |
| §4.3 `CryptoBehaviorMapper` | Task 2 |
| §4.4 output integration on `metadata.component` | Task 3 |
| §5 mapping table + primitive fallback | Task 2 |
| §5.1 taxonomy gaps (MAC, generic KDF) | Task 2 (code comments + tests) |
| §6 error handling (total mapper, empty→no property) | Task 2 (`map` guard), Task 3 (`isEmpty` guard) |
| §7 testing (mapper unit, sync, integration) | Tasks 1–3 |
| §4.5 curated detection (`generatesRandomValue`, `Cipher.unwrap`) | **Part B (separate plan)** |

## Deferred to Part B (separate plan)

- Wire the orphaned `java/.../detection/random` bundle into `JavaDetectionRules` and extend it to `SecureRandom.getInstance` / `getInstanceStrong` so a PRNG `Generate` signal reaches the mapper (`generatesRandomValue` from real detections).
- Add a `Cipher.unwrap` detection rule and verify `Cipher.wrap`/`WRAP_MODE` translate to an `Encapsulate`/`Decapsulate` functionality on a `Cipher` asset (so `wrapsKey` fires from real detections, not only synthetic test trees).
- Investigation tasks: confirm the current translation path for `CipherAction.WRAP` and the random package before writing rules.
