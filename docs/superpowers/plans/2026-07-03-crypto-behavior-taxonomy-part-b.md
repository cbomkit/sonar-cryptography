# Crypto Behavior Taxonomy (Part B: Curated Detection) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make two behaviors from Part A fire on *real scanned code* by adding the missing detections: `wrapsKey` (via `Cipher.unwrap` + the `KeyWrap` cipher-kind gap) and `generatesRandomValue` (via `SecureRandom` detection + a real PRNG model).

**Architecture:** Part A's `CryptoBehaviorMapper` already turns `Encapsulate`/`Decapsulate`-on-a-cipher into `wrapsKey` and `Generate`-on-a-PRNG into `generatesRandomValue`. Part B fills the *upstream* gaps so those node shapes actually get produced: it adds a `Cipher.unwrap` detection rule (mapping to `Decapsulate`), teaches the behavior mapper that `KeyWrap`-kind algorithms are ciphers, wires the orphaned `Random` detection bundle into the ruleset, adds `SecureRandom.getInstance`/`getInstanceStrong`/no-arg-constructor rules, creates a generic `PRNG` model, fills the `JcaPRNGMapper` `//todo` cases, and makes the PRNG translator attach a `Generate` functionality.

**Tech Stack:** Java 17, Maven multi-module, JUnit 5 + AssertJ, SonarQube `CheckVerifier` for detection tests.

**Spec:** `docs/superpowers/specs/2026-07-03-crypto-behavior-taxonomy-design.md` (§4.5).
**Builds on:** Part A (branch `feature/crypto-behavior-taxonomy`, PR #475). Part B commits go on the **same** branch.

**Scope note:** Data-context (`encryptsDataAtRest`/`InTransit`/`Disk`), KeyStore lifecycle, and PKI/cert behaviors remain deferred (spec §8). Part B is only the two curated detections.

## Global Constraints

- **Java 17.** No newer language features.
- **License header:** never hand-write it — `mvn spotless:apply` inserts the Apache 2.0 header. Run it before every commit.
- **Formatting:** Google Java Format (AOSP) via Spotless; **Checkstyle** forbids unused imports and requires `@Override`.
- **Module test commands** (Part B spans `engine`/`java`/`mapper`/`output`):
  - mapper unit tests: `mvn test -pl mapper -Dtest=<Class>`
  - output unit tests: `mvn test -pl output -am -Dtest=<Class>`
  - java detection tests: `mvn test -pl java -am -Dtest=<Class>` (`-am` compiles the `engine` enum change and `mapper`/`output` deps)
  - full regression before finishing: `mvn test`
- **`INode.is(Class)` is EXACT-kind match** (`getKind().equals(type)`), not `instanceof`. Enumerate concrete kinds.
- **Property name / identifier formats** are owned by Part A and unchanged here.
- **Branch:** `feature/crypto-behavior-taxonomy` (do not branch or switch).
- **Known flaky-build note:** builds intermittently truncate `mapper/.../ssl/json/JsonCipherSuites.java` in the working tree (a Spotless artifact). If `git status` shows it modified after a build, restore it with `git checkout -- <path>` before committing — never commit that truncation.

---

## Group A — `wrapsKey`

### Task 1: Detect `Cipher.unwrap` → `Decapsulate`

**Files:**
- Modify: `engine/src/main/java/com/ibm/engine/model/CipherAction.java`
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/jca/cipher/JcaCipherWrap.java`
- Modify: `java/src/main/java/com/ibm/plugin/translation/translator/contexts/JavaCipherContextTranslator.java`
- Create: `java/src/test/java/com/ibm/plugin/rules/detection/jca/cipher/JcaCipherUnwrapTest.java`
- Create: `java/src/test/files/rules/detection/jca/cipher/JcaCipherUnwrapTestFile.java`

**Interfaces:**
- Consumes: existing `CipherActionFactory`, `CipherContext`, `Decapsulate` functionality.
- Produces: `CipherAction.Action.UNWRAP`; a `JcaCipherWrap` rule for `unwrap`; a translated `Decapsulate` node for `UNWRAP`.

- [ ] **Step 1: Write the failing detection test**

Create `java/src/test/files/rules/detection/jca/cipher/JcaCipherUnwrapTestFile.java`:

```java
import java.security.Key;
import javax.crypto.Cipher;

public class JcaCipherUnwrapTestFile {

    public void test(byte[] wrapped) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        Key key = cipher.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
    }
}
```

Create `java/src/test/java/com/ibm/plugin/rules/detection/jca/cipher/JcaCipherUnwrapTest.java`:

```java
package com.ibm.plugin.rules.detection.jca.cipher;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.functionality.Decapsulate;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class JcaCipherUnwrapTest extends TestBase {

    protected JcaCipherUnwrapTest() {
        super(JcaCipherWrap.rules());
    }

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/jca/cipher/JcaCipherUnwrapTestFile.java")
                .withChecks(this)
                .verifyNoIssues();
    }

    private static boolean treeContainsKind(
            @Nonnull List<INode> nodes, @Nonnull Class<? extends INode> kind) {
        for (INode node : nodes) {
            if (node.is(kind)) {
                return true;
            }
            if (treeContainsKind(List.copyOf(node.getChildren().values()), kind)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(nodes).isNotEmpty();
        assertThat(treeContainsKind(nodes, Decapsulate.class))
                .as("unwrap should translate to a Decapsulate functionality")
                .isTrue();
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mvn test -pl java -am -Dtest=JcaCipherUnwrapTest`
Expected: FAIL — no `unwrap` rule exists, so either no finding is produced (empty `nodes`) or no `Decapsulate` node appears.

- [ ] **Step 3: Add `UNWRAP` to the `CipherAction` enum**

In `engine/src/main/java/com/ibm/engine/model/CipherAction.java`, add `UNWRAP` right after `WRAP`:

```java
    public enum Action {
        WRAP,
        UNWRAP,
        HASH,
        ENCRYPT,
        DECRYPT,
        PADDING,
        MAC,
        NONE
    }
```

- [ ] **Step 4: Add the `unwrap` detection rule**

In `java/src/main/java/com/ibm/plugin/rules/detection/jca/cipher/JcaCipherWrap.java`, add the static imports and the new rule, and include it in `rules()`. Add these static imports next to the existing `CIPHER_TYPE`/`KEY_TYPE` imports:

```java
import static com.ibm.plugin.rules.detection.TypeShortcuts.BYTE_ARRAY_TYPE;
import static com.ibm.plugin.rules.detection.TypeShortcuts.CIPHER_TYPE;
import static com.ibm.plugin.rules.detection.TypeShortcuts.KEY_TYPE;
import static com.ibm.plugin.rules.detection.TypeShortcuts.STRING_TYPE;
```

Add the rule field after `CIPHER_WRAP_1`:

```java
    private static final IDetectionRule<Tree> CIPHER_UNWRAP_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(CIPHER_TYPE)
                    .forMethods("unwrap")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.UNWRAP))
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .withMethodParameter(STRING_TYPE)
                    .withMethodParameter("int")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();
```

Update `rules()`:

```java
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(CIPHER_WRAP_1, CIPHER_UNWRAP_1);
    }
```

- [ ] **Step 5: Map `UNWRAP` → `Decapsulate` in the translator**

In `java/src/main/java/com/ibm/plugin/translation/translator/contexts/JavaCipherContextTranslator.java`, add the import `import com.ibm.mapper.model.functionality.Decapsulate;` (next to the existing `Encapsulate` import) and extend the `CipherAction` switch:

```java
        } else if (value instanceof CipherAction<Tree> cipherAction) {
            return switch (cipherAction.getAction()) {
                case WRAP -> Optional.of(new Encapsulate(detectionLocation));
                case UNWRAP -> Optional.of(new Decapsulate(detectionLocation));
                default -> Optional.empty();
            };
        }
```

- [ ] **Step 6: Format and run the test to verify it passes**

Run: `mvn spotless:apply -pl engine,java && mvn test -pl java -am -Dtest=JcaCipherUnwrapTest`
Expected: PASS. (If `git status` shows `JsonCipherSuites.java` modified, `git checkout --` it first.)

- [ ] **Step 7: Commit**

```bash
git add engine/src/main/java/com/ibm/engine/model/CipherAction.java \
        java/src/main/java/com/ibm/plugin/rules/detection/jca/cipher/JcaCipherWrap.java \
        java/src/main/java/com/ibm/plugin/translation/translator/contexts/JavaCipherContextTranslator.java \
        java/src/test/java/com/ibm/plugin/rules/detection/jca/cipher/JcaCipherUnwrapTest.java \
        java/src/test/files/rules/detection/jca/cipher/JcaCipherUnwrapTestFile.java
git commit -m "feat(java): detect Cipher.unwrap as Decapsulate (wrapsKey)"
```

---

### Task 2: Treat `KeyWrap`-kind algorithms as ciphers in `CryptoBehaviorMapper`

**Files:**
- Modify: `output/src/main/java/com/ibm/output/cyclondx/behavior/CryptoBehaviorMapper.java`
- Modify: `output/src/test/java/com/ibm/output/cyclonedx/behavior/CryptoBehaviorMapperTest.java`

**Interfaces:**
- Consumes: `com.ibm.mapper.model.KeyWrap` (the kind of named wrap ciphers `AESWrap`/`DESedeWrap`).
- Produces: `WRAPS_KEY` for `KeyWrap`-kind assets, both operationally (with `Encapsulate`/`Decapsulate`) and via the primitive fallback.

**Background:** Named wrap ciphers (`AESWrap`, `DESedeWrap`) get kind `KeyWrap`, which the mapper's `isCipher` check and fallback don't recognize, so they miss `wrapsKey`. `KeyWrap` is a wrap-only cipher, so it maps to `wrapsKey`.

- [ ] **Step 1: Write the failing tests**

In `output/src/test/java/com/ibm/output/cyclonedx/behavior/CryptoBehaviorMapperTest.java`, add the import `import com.ibm.mapper.model.KeyWrap;` (with the other `com.ibm.mapper.model` imports) and these two test methods:

```java
    @Test
    void encapsulateOnKeyWrapCipherYieldsWrapsKey() {
        final Algorithm aesWrap = new Algorithm("AESWrap", KeyWrap.class, loc);
        aesWrap.put(new Encapsulate(loc));
        assertThat(mapper.map(aesWrap)).containsExactly(CryptoBehavior.WRAPS_KEY);
    }

    @Test
    void bareKeyWrapCipherFallsBackToWrapsKey() {
        final Algorithm aesWrap = new Algorithm("AESWrap", KeyWrap.class, loc);
        assertThat(mapper.map(aesWrap)).containsExactly(CryptoBehavior.WRAPS_KEY);
    }
```

(The test's `loc` field and `mapper` field already exist from Part A; `Algorithm` and `Encapsulate` are already imported.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `mvn test -pl output -am -Dtest=CryptoBehaviorMapperTest`
Expected: FAIL — `KeyWrap`-kind assets currently produce an empty set (not counted as cipher, no fallback branch).

- [ ] **Step 3: Recognize `KeyWrap` in the mapper**

In `output/src/main/java/com/ibm/output/cyclondx/behavior/CryptoBehaviorMapper.java`, add the import `import com.ibm.mapper.model.KeyWrap;` (with the other `com.ibm.mapper.model` imports). Extend the `isCipher` computation to include `KeyWrap`:

```java
        final boolean isCipher =
                node.is(BlockCipher.class)
                        || node.is(StreamCipher.class)
                        || node.is(Cipher.class)
                        || node.is(AuthenticatedEncryption.class)
                        || node.is(KeyWrap.class);
```

Then add a `KeyWrap` branch to `applyPrimitiveFallback(...)`. Place it immediately after the `KeyEncapsulationMechanism` branch (a `KeyWrap` cipher wraps keys but does not do bulk encrypt/decrypt, so it must not fall into the generic-cipher branch):

```java
        } else if (node.is(KeyEncapsulationMechanism.class)) {
            behaviors.add(CryptoBehavior.EXCHANGES_KEY);
            behaviors.add(CryptoBehavior.ENSURES_CONFIDENTIALITY);
        } else if (node.is(KeyWrap.class)) {
            behaviors.add(CryptoBehavior.WRAPS_KEY);
        } else if (node.is(KeyAgreement.class)) {
```

Note: because `KeyWrap` is now in `isCipher`, an `Encapsulate`/`Decapsulate` on a `KeyWrap` asset already yields `WRAPS_KEY` in the operational pass (the `else if (isCipher)` branch). The fallback branch covers a bare `KeyWrap` asset with no detected operation.

- [ ] **Step 4: Format and run the tests to verify they pass**

Run: `mvn spotless:apply -pl output && mvn test -pl output -am -Dtest=CryptoBehaviorMapperTest`
Expected: PASS — the two new tests plus all pre-existing mapper tests.

- [ ] **Step 5: Commit**

```bash
git add output/src/main/java/com/ibm/output/cyclondx/behavior/CryptoBehaviorMapper.java \
        output/src/test/java/com/ibm/output/cyclonedx/behavior/CryptoBehaviorMapperTest.java
git commit -m "feat(output): map KeyWrap-kind ciphers to wrapsKey"
```

---

## Group B — `generatesRandomValue`

### Task 3: Generic `PRNG` model + fill `JcaPRNGMapper`

**Files:**
- Create: `mapper/src/main/java/com/ibm/mapper/model/algorithms/PRNG.java`
- Modify: `mapper/src/main/java/com/ibm/mapper/mapper/jca/JcaPRNGMapper.java`
- Modify: `mapper/src/test/java/com/ibm/mapper/mapper/jca/JcaPRNGMapperTest.java`

**Interfaces:**
- Produces: `PRNG` — an `Algorithm` of kind `PseudorandomNumberGenerator`, name `"PRNG"`, no children.
- `JcaPRNGMapper.parse(str, loc)` returns `Optional.of(new PRNG(loc))` for the DRBG algorithm names (previously `//todo` empty).

- [ ] **Step 1: Un-disable the existing PRNG mapper test (this is the failing test)**

In `mapper/src/test/java/com/ibm/mapper/mapper/jca/JcaPRNGMapperTest.java`, remove the `@Disabled` annotation (and its import) from the `base()` test. The test already asserts `parse("NativePRNGBlocking")` is present, is a `PseudorandomNumberGenerator`, has name `"PRNG"`, and has no children.

- [ ] **Step 2: Run the test to verify it fails**

Run: `mvn test -pl mapper -Dtest=JcaPRNGMapperTest`
Expected: FAIL on `base()` — `parse("NativePRNGBlocking")` currently returns `Optional.empty()` (the `//todo` branch), so `assertThat(prngOptional).isPresent()` fails. (`sha1prng()` still passes.)

- [ ] **Step 3: Create the `PRNG` model**

Create `mapper/src/main/java/com/ibm/mapper/model/algorithms/PRNG.java`:

```java
package com.ibm.mapper.model.algorithms;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>{@value #NAME}</h2>
 *
 * <p>Generic pseudorandom number generator, used when a specific PRNG/DRBG algorithm is requested
 * (e.g. via {@code SecureRandom.getInstance("DRBG")}) but no more specific model applies.
 */
public final class PRNG extends Algorithm implements PseudorandomNumberGenerator {
    private static final String NAME = "PRNG";

    public PRNG(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, PseudorandomNumberGenerator.class, detectionLocation);
    }
}
```

- [ ] **Step 4: Fill the `//todo` cases in `JcaPRNGMapper`**

In `mapper/src/main/java/com/ibm/mapper/mapper/jca/JcaPRNGMapper.java`, add the import `import com.ibm.mapper.model.algorithms.PRNG;` and replace the empty DRBG switch arm with a real `PRNG`:

```java
        return switch (str.toUpperCase().trim()) {
            case "NATIVEPRNG",
                    "DRBG",
                    "NATIVEPRNGBLOCKING",
                    "NATIVEPRNGNONBLOCKING",
                    "WINDOWS-PRNG" ->
                    Optional.of(new PRNG(detectionLocation));
            default -> Optional.empty();
        };
```

- [ ] **Step 5: Format and run the test to verify it passes**

Run: `mvn spotless:apply -pl mapper && mvn test -pl mapper -Dtest=JcaPRNGMapperTest`
Expected: PASS — both `base()` and `sha1prng()`.

- [ ] **Step 6: Commit**

```bash
git add mapper/src/main/java/com/ibm/mapper/model/algorithms/PRNG.java \
        mapper/src/main/java/com/ibm/mapper/mapper/jca/JcaPRNGMapper.java \
        mapper/src/test/java/com/ibm/mapper/mapper/jca/JcaPRNGMapperTest.java
git commit -m "feat(mapper): add generic PRNG model and map JCA DRBG names"
```

---

### Task 4: Detect `SecureRandom`, register the bundle, translate to `PRNG` + `Generate`

**Files:**
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/random/SecureRandomGetInstance.java`
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/JavaDetectionRules.java`
- Modify: `java/src/main/java/com/ibm/plugin/translation/translator/contexts/JavaPRNGContextTranslator.java`
- Modify: `java/src/test/java/com/ibm/plugin/rules/detection/random/SecureRandomGetInstanceTest.java`
- Modify: `java/src/test/files/rules/detection/random/SecureRandomGetInstanceTestFile.java`

**Interfaces:**
- Consumes: `PRNG` model + `JcaPRNGMapper` (Task 3); `AlgorithmFactory`, `ValueActionFactory`, `PRNGContext`, `Generate`, `Seed`.
- Produces: detection of `SecureRandom.getInstance(String)`, `SecureRandom.getInstanceStrong()`, and no-arg `new SecureRandom()`, all translated to a `PseudorandomNumberGenerator` asset carrying a `Generate` functionality → `generatesRandomValue` in Part A's mapper.

- [ ] **Step 1: Write the failing detection test**

Replace the body of `java/src/test/files/rules/detection/random/SecureRandomGetInstanceTestFile.java`:

```java
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SecureRandomGetInstanceTestFile {

    public void test() throws NoSuchAlgorithmException {
        byte[] seed = "1245".getBytes();
        SecureRandom seeded = new SecureRandom(seed);
        SecureRandom byName = SecureRandom.getInstance("DRBG");
        SecureRandom strong = SecureRandom.getInstanceStrong();
        SecureRandom def = new SecureRandom();
    }
}
```

Rewrite `java/src/test/java/com/ibm/plugin/rules/detection/random/SecureRandomGetInstanceTest.java`'s `asserts(...)` (keep the class/imports; add the ones below) so every finding must translate to a PRNG carrying a `Generate`:

```java
    private static boolean treeContainsKind(
            @Nonnull List<INode> nodes, @Nonnull Class<? extends INode> kind) {
        for (INode node : nodes) {
            if (node.is(kind)) {
                return true;
            }
            if (treeContainsKind(List.copyOf(node.getChildren().values()), kind)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(nodes).as("finding %d should translate to a node", findingId).isNotEmpty();
        assertThat(treeContainsKind(nodes, PseudorandomNumberGenerator.class))
                .as("finding %d should be a PseudorandomNumberGenerator", findingId)
                .isTrue();
        assertThat(treeContainsKind(nodes, Generate.class))
                .as("finding %d should carry a Generate functionality", findingId)
                .isTrue();
    }
```

Add these imports to the test class:

```java
import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.functionality.Generate;
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mvn test -pl java -am -Dtest=SecureRandomGetInstanceTest`
Expected: FAIL — the `Random` bundle is not registered (so no findings are produced / `verifyNoIssues` sees no translated nodes), and the translator attaches `Seed` rather than `Generate`.

- [ ] **Step 3: Add the `SecureRandom` detection rules**

In `java/src/main/java/com/ibm/plugin/rules/detection/random/SecureRandomGetInstance.java`, add these imports:

```java
import static com.ibm.plugin.rules.detection.TypeShortcuts.STRING_TYPE;

import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
```

Add three rule fields after `SECURE_RANDOM_3`:

```java
    private static final IDetectionRule<Tree> SECURE_RANDOM_GET_INSTANCE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.SecureRandom")
                    .forMethods("getInstance")
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "Random")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SECURE_RANDOM_GET_INSTANCE_STRONG =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.SecureRandom")
                    .forMethods("getInstanceStrong")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DRBG"))
                    .withoutParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "Random")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SECURE_RANDOM_NO_ARG =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.SecureRandom")
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>("NativePRNG"))
                    .withoutParameters()
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "Random")
                    .withoutDependingDetectionRules();
```

Update `rules()`:

```java
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                SECURE_RANDOM_1,
                SECURE_RANDOM_2,
                SECURE_RANDOM_3,
                SECURE_RANDOM_GET_INSTANCE,
                SECURE_RANDOM_GET_INSTANCE_STRONG,
                SECURE_RANDOM_NO_ARG);
    }
```

- [ ] **Step 4: Register the `Random` bundle in `JavaDetectionRules`**

In `java/src/main/java/com/ibm/plugin/rules/detection/JavaDetectionRules.java`, add the import `import com.ibm.plugin.rules.detection.random.SecureRandomGetInstance;` and add its stream to the aggregation:

```java
        return Stream.of(
                        JcaDetectionRules.rules().stream(),
                        BouncyCastleDetectionRules.rules().stream(),
                        SSLDetectionRules.rules().stream(),
                        SecureRandomGetInstance.rules().stream())
                .flatMap(i -> i)
                .toList();
```

- [ ] **Step 5: Make the PRNG translator attach `Generate`**

Replace the body of `translate(...)` in `java/src/main/java/com/ibm/plugin/translation/translator/contexts/JavaPRNGContextTranslator.java` so it (a) parses the captured algorithm string (from `Algorithm`/`ValueAction` values) instead of the hardcoded `"NativePRNG"`, and (b) attaches a `Generate` functionality (the `Seed` is still attached on the seed-size path):

```java
        if (!bundleIdentifier.getIdentifier().equals("Random")) {
            return Optional.empty();
        }

        final JcaPRNGMapper jcaPRNGMapper = new JcaPRNGMapper();

        if (value instanceof SeedSize<Tree> seedSize) {
            return jcaPRNGMapper
                    .parse("NativePRNG", detectionLocation)
                    .map(
                            prng -> {
                                prng.put(new Seed(seedSize.getValue(), detectionLocation));
                                prng.put(new Generate(detectionLocation));
                                return (INode) prng;
                            });
        }

        if (value instanceof Algorithm<?> || value instanceof ValueAction<?>) {
            return jcaPRNGMapper
                    .parse(value.asString(), detectionLocation)
                    .map(
                            prng -> {
                                prng.put(new Generate(detectionLocation));
                                return (INode) prng;
                            });
        }
        return Optional.empty();
```

Add these imports (with the existing engine/mapper imports):

```java
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.ValueAction;
import com.ibm.mapper.model.functionality.Generate;
```

(Keep the existing `SeedSize`, `Seed`, `JcaPRNGMapper`, `INode`, `IPrimitive` imports; `IPrimitive` may become unused after the rewrite — if Checkstyle flags it, remove it.)

- [ ] **Step 6: Format and run the test to verify it passes**

Run: `mvn spotless:apply -pl java && mvn test -pl java -am -Dtest=SecureRandomGetInstanceTest`
Expected: PASS — every finding (seeded ctor, `getInstance("DRBG")`, `getInstanceStrong()`, no-arg ctor) translates to a PRNG carrying a `Generate`. (If `git status` shows `JsonCipherSuites.java` modified, `git checkout --` it before committing.)

- [ ] **Step 7: Commit**

```bash
git add java/src/main/java/com/ibm/plugin/rules/detection/random/SecureRandomGetInstance.java \
        java/src/main/java/com/ibm/plugin/rules/detection/JavaDetectionRules.java \
        java/src/main/java/com/ibm/plugin/translation/translator/contexts/JavaPRNGContextTranslator.java \
        java/src/test/java/com/ibm/plugin/rules/detection/random/SecureRandomGetInstanceTest.java \
        java/src/test/files/rules/detection/random/SecureRandomGetInstanceTestFile.java
git commit -m "feat(java): detect SecureRandom usage as PRNG with Generate (generatesRandomValue)"
```

---

## Verification (end of plan)

- [ ] `mvn test` (full multi-module regression) — all modules green. If it truncates `JsonCipherSuites.java`, restore before any commit.
- [ ] `mvn spotless:check` and `mvn checkstyle:check` — clean (no unused imports; watch the possibly-unused `IPrimitive` import in the PRNG translator).
- [ ] Sanity: a scan of code using `Cipher.unwrap`, `AESWrap`, and `SecureRandom.getInstance(...)` now contributes `security:cryptography:wrapsKey` and `security:cryptography:generatesRandomValue` to the `metadata.component` behavior property (Part A emission).

## Spec coverage map

| Spec §4.5 item | Task |
|---|---|
| `Cipher.unwrap` detection → `wrapsKey` | Task 1 |
| `KeyWrap`-kind ciphers → `wrapsKey` (gap found in review) | Task 2 |
| Generic PRNG model + JCA DRBG mapping | Task 3 |
| Wire orphaned `Random` bundle + `SecureRandom.getInstance`/`getInstanceStrong`/no-arg detection + `Generate` attach → `generatesRandomValue` | Task 4 |

## Notes / deliberate limitations

- `SecureRandom.getInstance("SHA1PRNG")` already maps (via `JcaPRNGMapper`) to an `SHA`-as-PRNG node; with Task 4 it now also gets a `Generate` and yields `generatesRandomValue`.
- Arbitrary/unknown algorithm strings passed to `getInstance` fall through `JcaPRNGMapper`'s `default -> Optional.empty()` and produce no node (conservative — no wrong data). The common named DRBGs and the fixed constants used by `getInstanceStrong()`/no-arg are covered.
- The seed-size path (`new SecureRandom(byte[])` / `setSeed`) continues to model the PRNG as generic `"NativePRNG"` (no algorithm string is available from a seed), now additionally carrying `Generate`.
