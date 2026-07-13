# Behavior Subsystem Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the crypto-behavior feature out of `CBOMOutputFile` into a self-contained `com.ibm.output.behavior` subsystem with a unified signal model and rule registry, per spec `docs/superpowers/specs/2026-07-13-behavior-subsystem-refactor-design.md`.

**Architecture:** A `BehaviorCollector` becomes the only behavior object `CBOMOutputFile` talks to (`observe(INode)` during collection, `inferBehaviors()` at emission). Inference runs an ordered list of `IBehaviorRule`s over one immutable `BehaviorSignals` snapshot, replacing the two-input `BehaviorInferenceEngine`. The mapper becomes declarative tables and stops emitting `AUTHENTICATES` (that behavior is owned by `AuthInterfaceRule`). CycloneDX-specific formatting moves to `BehaviorMetadataWriter`.

**Tech Stack:** Java 17, Maven multi-module, JUnit 5 + AssertJ, Spotless (Google Java Format, AOSP), Checkstyle.

## Global Constraints

- **Only the `output` module changes.** No edits in engine/java/python/mapper.
- **Emitted CBOM must stay byte-identical.** `CryptoBehaviorMetadataTest` is the regression anchor — its assertions must never change (only its imports may).
- **License headers:** do NOT hand-write the 19-line Apache header in new files; `mvn spotless:apply` inserts/normalizes it. Run it before each commit.
- **Spotless hazard:** `mvn spotless:apply` intermittently truncates the huge generated `JsonCipherSuites` file. After every spotless run, check `git status` — if any `JsonCipherSuites*.java` shows as modified, restore it with `git checkout -- <path>` before committing.
- **Checkstyle:** no unused imports; utility classes need a private constructor; `@Override` required.
- **Test command:** `mvn test -pl output` (add `-Dtest=<Class>` for one class). If it fails with unresolved `com.ibm:*` dependencies, run `mvn install -DskipTests -q` once at the repo root first.
- **Commit style:** plain imperative sentence, no conventional-commit prefix (matches repo history, e.g. "Add .superpowers to gitignore").
- **Main source package is `cyclondx` (existing spelling, keep it); new packages are `com.ibm.output.behavior[.rules]`.**

---

### Task 1: Move `CryptoBehavior` and `CryptoBehaviorMapper` to `com.ibm.output.behavior`

Pure mechanical move — no semantic change, everything stays green.

**Files:**
- Move: `output/src/main/java/com/ibm/output/cyclondx/behavior/CryptoBehavior.java` → `output/src/main/java/com/ibm/output/behavior/CryptoBehavior.java`
- Move: `output/src/main/java/com/ibm/output/cyclondx/behavior/CryptoBehaviorMapper.java` → `output/src/main/java/com/ibm/output/behavior/CryptoBehaviorMapper.java`
- Move: `output/src/test/java/com/ibm/output/cyclonedx/behavior/CryptoBehaviorMapperTest.java` → `output/src/test/java/com/ibm/output/behavior/CryptoBehaviorMapperTest.java`
- Move: `output/src/test/java/com/ibm/output/cyclonedx/behavior/CryptoBehaviorTaxonomyTest.java` → `output/src/test/java/com/ibm/output/behavior/CryptoBehaviorTaxonomyTest.java`
- Modify: `output/src/main/java/com/ibm/output/cyclondx/CBOMOutputFile.java` (imports only)
- Modify: `output/src/main/java/com/ibm/output/cyclondx/behavior/BehaviorInferenceEngine.java` (import only)
- Modify: `output/src/test/java/com/ibm/output/cyclonedx/behavior/BehaviorInferenceEngineTest.java` (import only)
- Modify: `output/src/test/java/com/ibm/output/cyclonedx/CryptoBehaviorMetadataTest.java` (import only)

**Interfaces:**
- Consumes: nothing new.
- Produces: `com.ibm.output.behavior.CryptoBehavior` (enum, unchanged API: `fullId()`), `com.ibm.output.behavior.CryptoBehaviorMapper` (unchanged API: `Set<CryptoBehavior> map(INode)`, `String BEHAVIOR_PROPERTY_NAME` — the constant moves away in Task 5).

- [ ] **Step 1: Move the main files with git mv**

```bash
mkdir -p output/src/main/java/com/ibm/output/behavior
git mv output/src/main/java/com/ibm/output/cyclondx/behavior/CryptoBehavior.java output/src/main/java/com/ibm/output/behavior/CryptoBehavior.java
git mv output/src/main/java/com/ibm/output/cyclondx/behavior/CryptoBehaviorMapper.java output/src/main/java/com/ibm/output/behavior/CryptoBehaviorMapper.java
```

- [ ] **Step 2: Update package declarations in the two moved main files**

In both `CryptoBehavior.java` and `CryptoBehaviorMapper.java`:

```java
// old
package com.ibm.output.cyclondx.behavior;
// new
package com.ibm.output.behavior;
```

- [ ] **Step 3: Fix the three main-source references**

`CBOMOutputFile.java` — imports (leave the `BehaviorInferenceEngine` import as is):

```java
// old
import com.ibm.output.cyclondx.behavior.CryptoBehavior;
import com.ibm.output.cyclondx.behavior.CryptoBehaviorMapper;
// new
import com.ibm.output.behavior.CryptoBehavior;
import com.ibm.output.behavior.CryptoBehaviorMapper;
```

`BehaviorInferenceEngine.java` — it used `CryptoBehavior` from its own package, so it needs a new import. Add to the import block:

```java
import com.ibm.output.behavior.CryptoBehavior;
```

- [ ] **Step 4: Move the two test files and fix their packages/imports**

```bash
mkdir -p output/src/test/java/com/ibm/output/behavior
git mv output/src/test/java/com/ibm/output/cyclonedx/behavior/CryptoBehaviorMapperTest.java output/src/test/java/com/ibm/output/behavior/CryptoBehaviorMapperTest.java
git mv output/src/test/java/com/ibm/output/cyclonedx/behavior/CryptoBehaviorTaxonomyTest.java output/src/test/java/com/ibm/output/behavior/CryptoBehaviorTaxonomyTest.java
```

In both moved test files change the package to `com.ibm.output.behavior` and DELETE the now-same-package imports:

```java
// package line in both files
package com.ibm.output.behavior;

// DELETE from CryptoBehaviorMapperTest.java:
import com.ibm.output.cyclondx.behavior.CryptoBehavior;
import com.ibm.output.cyclondx.behavior.CryptoBehaviorMapper;

// DELETE from CryptoBehaviorTaxonomyTest.java:
import com.ibm.output.cyclondx.behavior.CryptoBehavior;
```

- [ ] **Step 5: Fix the two remaining test references**

`output/src/test/java/com/ibm/output/cyclonedx/behavior/BehaviorInferenceEngineTest.java`:

```java
// old
import com.ibm.output.cyclondx.behavior.CryptoBehavior;
// new
import com.ibm.output.behavior.CryptoBehavior;
```

`output/src/test/java/com/ibm/output/cyclonedx/CryptoBehaviorMetadataTest.java`:

```java
// old
import com.ibm.output.cyclondx.behavior.CryptoBehaviorMapper;
// new
import com.ibm.output.behavior.CryptoBehaviorMapper;
```

- [ ] **Step 6: Verify green**

Run: `mvn test -pl output`
Expected: BUILD SUCCESS, all tests pass (same count as before the move).

- [ ] **Step 7: Format and commit**

```bash
mvn spotless:apply -pl output -q
git status   # if any JsonCipherSuites*.java is modified: git checkout -- <path>
git add -A output
git commit -m "Move crypto behavior taxonomy and mapper to com.ibm.output.behavior"
```

---

### Task 2: Table-ize `CryptoBehaviorMapper` and stop deriving `authenticates`

TDD: retighten the Mac/Tag expectations first (they must fail), then replace the if-chains with declarative tables. End-to-end output is unchanged because `BehaviorInferenceEngine` still strips `AUTHENTICATES` when no auth primary exists — after this task the strip is simply a no-op.

**Files:**
- Modify: `output/src/main/java/com/ibm/output/behavior/CryptoBehaviorMapper.java` (full rewrite of the class body)
- Test: `output/src/test/java/com/ibm/output/behavior/CryptoBehaviorMapperTest.java`

**Interfaces:**
- Consumes: `CryptoBehavior` (Task 1 location).
- Produces: `CryptoBehaviorMapper.map(INode)` with new contract: **never returns `AUTHENTICATES`**. `BEHAVIOR_PROPERTY_NAME` still present (removed in Task 5). Task 4's collector calls `map()`.

- [ ] **Step 1: Update the two authenticates expectations and add the first-match test**

In `CryptoBehaviorMapperTest.java`, replace these two tests:

```java
    @Test
    void bareMacFallsBackToIntegrityOnly() {
        // authenticates is application-level and gated on auth-interface evidence; a bare MAC
        // contributes only the integrity goal (spec 2026-07-13 §4).
        final HMAC hmac = new HMAC(loc);
        assertThat(mapper.map(hmac)).containsExactly(CryptoBehavior.ENSURES_INTEGRITY);
    }

    @Test
    void tagOperationYieldsIntegrityOnly() {
        final HMAC hmac = new HMAC(loc);
        hmac.put(new Tag(loc));
        assertThat(mapper.map(hmac)).containsExactly(CryptoBehavior.ENSURES_INTEGRITY);
    }
```

(They replace `bareMacFallsBackToAuthenticatesAndIntegrity` and `tagOperationYieldsAuthenticatesAndIntegrity`.)

And add this test at the end of the class:

```java
    @Test
    void fallbackFirstMatchWins() {
        // AuthenticatedEncryption must resolve via its own row (four behaviors), not a generic
        // cipher row — guards the ordered, first-match-wins contract of the fallback table.
        final Algorithm aesgcm = new Algorithm("AES-GCM", AuthenticatedEncryption.class, loc);
        assertThat(mapper.map(aesgcm)).hasSize(4).contains(CryptoBehavior.ENSURES_INTEGRITY);
    }
```

- [ ] **Step 2: Run to verify the two changed tests fail**

Run: `mvn test -pl output -Dtest=CryptoBehaviorMapperTest`
Expected: FAIL — `bareMacFallsBackToIntegrityOnly` and `tagOperationYieldsIntegrityOnly` fail (actual sets still contain `AUTHENTICATES`); `fallbackFirstMatchWins` passes already.

- [ ] **Step 3: Rewrite the mapper as tables**

Replace the entire class body of `CryptoBehaviorMapper.java` (keep the license header) with:

```java
package com.ibm.output.behavior;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.KeyWrap;
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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import javax.annotation.Nonnull;

/**
 * Derives {@link CryptoBehavior}s for a detected cryptographic asset. Operation-first: every
 * {@code OPERATIONS} row whose {@code Functionality} child is present and whose guard holds
 * contributes. If no operation matched, the ordered {@code FALLBACKS} table infers plausible
 * behaviors from the primitive kind (first matching kind wins). Never throws; unmappable input
 * yields an empty set. Note: {@code authenticates} is deliberately never derived here — it is an
 * application-level behavior gated on auth-interface evidence (see {@code AuthInterfaceRule}).
 */
public final class CryptoBehaviorMapper {

    public static final String BEHAVIOR_PROPERTY_NAME = "cbomkit:crypto:behavior";

    private static final Predicate<INode> ANY = node -> true;

    private static final Predicate<INode> IS_KEM =
            node -> node.is(KeyEncapsulationMechanism.class);

    private static final Predicate<INode> IS_CIPHER =
            node ->
                    node.is(BlockCipher.class)
                            || node.is(StreamCipher.class)
                            || node.is(Cipher.class)
                            || node.is(AuthenticatedEncryption.class)
                            || node.is(KeyWrap.class);

    private static final Predicate<INode> IS_PRNG =
            node -> node.is(PseudorandomNumberGenerator.class);

    private static final Predicate<INode> IS_PASSWORD_KDF =
            node ->
                    node.is(PasswordBasedKeyDerivationFunction.class)
                            || node.is(PasswordBasedEncryption.class);

    private record OperationMapping(
            @Nonnull Class<? extends INode> operation,
            @Nonnull Predicate<INode> when,
            @Nonnull Set<CryptoBehavior> behaviors) {}

    private record FallbackMapping(
            @Nonnull Class<? extends INode> primitive, @Nonnull Set<CryptoBehavior> behaviors) {}

    /** Operational pass (spec §5.1) — all matching rows contribute. */
    private static final List<OperationMapping> OPERATIONS =
            List.of(
                    on(
                            Encrypt.class,
                            ANY,
                            CryptoBehavior.ENCRYPTS_DATA,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    on(
                            Decrypt.class,
                            ANY,
                            CryptoBehavior.DECRYPTS_DATA,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    on(
                            Encapsulate.class,
                            IS_KEM,
                            CryptoBehavior.EXCHANGES_KEY,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    on(
                            Decapsulate.class,
                            IS_KEM,
                            CryptoBehavior.EXCHANGES_KEY,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    // JCA WRAP_MODE/UNWRAP_MODE and Cipher.wrap surface as (De)Encapsulate on a
                    // Cipher.
                    on(Encapsulate.class, IS_CIPHER, CryptoBehavior.WRAPS_KEY),
                    on(Decapsulate.class, IS_CIPHER, CryptoBehavior.WRAPS_KEY),
                    on(
                            Sign.class,
                            ANY,
                            CryptoBehavior.SIGNS_DATA,
                            CryptoBehavior.ENSURES_INTEGRITY,
                            CryptoBehavior.ENSURES_NON_REPUDIATION),
                    on(
                            Verify.class,
                            ANY,
                            CryptoBehavior.VERIFIES_SIGNATURE,
                            CryptoBehavior.ENSURES_INTEGRITY),
                    on(
                            Digest.class,
                            ANY,
                            CryptoBehavior.HASHES_DATA,
                            CryptoBehavior.ENSURES_INTEGRITY),
                    // No operational "computesMac" verb in the taxonomy, and authenticates is
                    // gated on auth-interface evidence — a Tag contributes integrity only.
                    on(Tag.class, ANY, CryptoBehavior.ENSURES_INTEGRITY),
                    on(Generate.class, IS_PRNG, CryptoBehavior.GENERATES_RANDOM_VALUE),
                    on(KeyGeneration.class, ANY, CryptoBehavior.GENERATES_KEY),
                    on(KeyDerivation.class, IS_PASSWORD_KDF, CryptoBehavior.HASHES_PASSWORD),
                    // Generic KDF has no "deriveKey" value; approximated as generatesKey (spec
                    // §5.1).
                    on(
                            KeyDerivation.class,
                            IS_PASSWORD_KDF.negate(),
                            CryptoBehavior.GENERATES_KEY));

    /** Primitive-kind fallback (spec §5.2) — ordered, the first matching kind wins. */
    private static final List<FallbackMapping> FALLBACKS =
            List.of(
                    fallback(
                            AuthenticatedEncryption.class,
                            CryptoBehavior.ENCRYPTS_DATA,
                            CryptoBehavior.DECRYPTS_DATA,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY,
                            CryptoBehavior.ENSURES_INTEGRITY),
                    fallback(
                            BlockCipher.class,
                            CryptoBehavior.ENCRYPTS_DATA,
                            CryptoBehavior.DECRYPTS_DATA,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    fallback(
                            StreamCipher.class,
                            CryptoBehavior.ENCRYPTS_DATA,
                            CryptoBehavior.DECRYPTS_DATA,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    fallback(
                            Cipher.class,
                            CryptoBehavior.ENCRYPTS_DATA,
                            CryptoBehavior.DECRYPTS_DATA,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    fallback(
                            PublicKeyEncryption.class,
                            CryptoBehavior.ENCRYPTS_DATA,
                            CryptoBehavior.DECRYPTS_DATA,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    fallback(
                            Signature.class,
                            CryptoBehavior.SIGNS_DATA,
                            CryptoBehavior.VERIFIES_SIGNATURE,
                            CryptoBehavior.ENSURES_INTEGRITY,
                            CryptoBehavior.ENSURES_NON_REPUDIATION),
                    fallback(
                            ProbabilisticSignatureScheme.class,
                            CryptoBehavior.SIGNS_DATA,
                            CryptoBehavior.VERIFIES_SIGNATURE,
                            CryptoBehavior.ENSURES_INTEGRITY,
                            CryptoBehavior.ENSURES_NON_REPUDIATION),
                    fallback(
                            MessageDigest.class,
                            CryptoBehavior.HASHES_DATA,
                            CryptoBehavior.ENSURES_INTEGRITY),
                    // A bare MAC ensures integrity; authenticates is gated on auth-interface
                    // evidence.
                    fallback(Mac.class, CryptoBehavior.ENSURES_INTEGRITY),
                    fallback(
                            KeyEncapsulationMechanism.class,
                            CryptoBehavior.EXCHANGES_KEY,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    fallback(KeyWrap.class, CryptoBehavior.WRAPS_KEY),
                    fallback(KeyAgreement.class, CryptoBehavior.EXCHANGES_KEY),
                    fallback(
                            PasswordBasedKeyDerivationFunction.class,
                            CryptoBehavior.HASHES_PASSWORD),
                    fallback(PasswordBasedEncryption.class, CryptoBehavior.HASHES_PASSWORD),
                    fallback(KeyDerivationFunction.class, CryptoBehavior.GENERATES_KEY),
                    fallback(
                            PseudorandomNumberGenerator.class,
                            CryptoBehavior.GENERATES_RANDOM_VALUE));

    @Nonnull
    public Set<CryptoBehavior> map(@Nonnull INode node) {
        final Set<CryptoBehavior> behaviors = EnumSet.noneOf(CryptoBehavior.class);
        if (!(node instanceof Algorithm)) {
            return behaviors;
        }
        final Map<Class<? extends INode>, INode> children = node.getChildren();
        for (OperationMapping row : OPERATIONS) {
            if (children.containsKey(row.operation()) && row.when().test(node)) {
                behaviors.addAll(row.behaviors());
            }
        }
        if (behaviors.isEmpty()) {
            for (FallbackMapping row : FALLBACKS) {
                if (node.is(row.primitive())) {
                    behaviors.addAll(row.behaviors());
                    break;
                }
            }
        }
        return behaviors;
    }

    private static OperationMapping on(
            @Nonnull Class<? extends INode> operation,
            @Nonnull Predicate<INode> when,
            @Nonnull CryptoBehavior... behaviors) {
        return new OperationMapping(operation, when, Set.of(behaviors));
    }

    private static FallbackMapping fallback(
            @Nonnull Class<? extends INode> primitive, @Nonnull CryptoBehavior... behaviors) {
        return new FallbackMapping(primitive, Set.of(behaviors));
    }
}
```

- [ ] **Step 4: Run the whole output module**

Run: `mvn test -pl output`
Expected: BUILD SUCCESS. Mapper tests pass with new expectations; `BehaviorInferenceEngineTest` and `CryptoBehaviorMetadataTest` pass unchanged (the engine's strip of `AUTHENTICATES` is now a no-op; the emitted property was never affected).

- [ ] **Step 5: Format and commit**

```bash
mvn spotless:apply -pl output -q
git status   # restore JsonCipherSuites*.java if touched
git add -A output
git commit -m "Table-ize CryptoBehaviorMapper and stop deriving authenticates from crypto"
```

---

### Task 3: Signal model and inference rules

New classes only, nothing wired yet. TDD per rule.

**Files:**
- Create: `output/src/main/java/com/ibm/output/behavior/BehaviorSignals.java`
- Create: `output/src/main/java/com/ibm/output/behavior/IBehaviorRule.java`
- Create: `output/src/main/java/com/ibm/output/behavior/rules/CryptoBehaviorRule.java`
- Create: `output/src/main/java/com/ibm/output/behavior/rules/AuthInterfaceRule.java`
- Test: `output/src/test/java/com/ibm/output/behavior/rules/AuthInterfaceRuleTest.java`
- Test: `output/src/test/java/com/ibm/output/behavior/rules/CryptoBehaviorRuleTest.java`

**Interfaces:**
- Consumes: `CryptoBehavior` (Task 1), `com.ibm.engine.model.context.AuthContext.Kind` (existing engine enum).
- Produces (used by Task 4):
  - `record BehaviorSignals(Set<CryptoBehavior> cryptoBehaviors, Set<AuthContext.Kind> authKinds)` — canonical constructor takes both sets, stores immutable copies.
  - `interface IBehaviorRule { Set<CryptoBehavior> apply(BehaviorSignals signals); }`
  - `class CryptoBehaviorRule implements IBehaviorRule` (no-arg ctor)
  - `class AuthInterfaceRule implements IBehaviorRule` (no-arg ctor)

- [ ] **Step 1: Create the signal model and rule interface**

`output/src/main/java/com/ibm/output/behavior/BehaviorSignals.java` (spotless adds the header):

```java
package com.ibm.output.behavior;

import com.ibm.engine.model.context.AuthContext;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Immutable snapshot of every behavior-relevant signal observed during a scan — the single input
 * to each {@link IBehaviorRule}. A future evidence family (certificates, code signing) adds one
 * component here, one observe branch in {@link BehaviorCollector}, and one rule; nothing else
 * changes.
 */
public record BehaviorSignals(
        @Nonnull Set<CryptoBehavior> cryptoBehaviors, @Nonnull Set<AuthContext.Kind> authKinds) {

    public BehaviorSignals {
        cryptoBehaviors = Set.copyOf(cryptoBehaviors);
        authKinds = Set.copyOf(authKinds);
    }
}
```

`output/src/main/java/com/ibm/output/behavior/IBehaviorRule.java`:

```java
package com.ibm.output.behavior;

import java.util.Set;
import javax.annotation.Nonnull;

/**
 * One inference rule: examines the scan-wide {@link BehaviorSignals} and returns the behaviors it
 * can justify. Rules are independent — contributing nothing is normal — and the collector unions
 * their results. Implementations must be total and side-effect free.
 */
public interface IBehaviorRule {

    @Nonnull
    Set<CryptoBehavior> apply(@Nonnull BehaviorSignals signals);
}
```

- [ ] **Step 2: Write the failing AuthInterfaceRule test**

`output/src/test/java/com/ibm/output/behavior/rules/AuthInterfaceRuleTest.java`:

```java
package com.ibm.output.behavior.rules;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.output.behavior.BehaviorSignals;
import com.ibm.output.behavior.CryptoBehavior;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AuthInterfaceRuleTest {

    private final AuthInterfaceRule rule = new AuthInterfaceRule();

    private BehaviorSignals signalsOf(AuthContext.Kind... kinds) {
        return new BehaviorSignals(Set.of(), Set.of(kinds));
    }

    @Test
    void jwtYieldsAuthenticatesAndValidatesToken() {
        assertThat(rule.apply(signalsOf(AuthContext.Kind.JWT)))
                .containsOnly(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN);
    }

    @Test
    void oauthYieldsAuthenticatesAndValidatesToken() {
        assertThat(rule.apply(signalsOf(AuthContext.Kind.OAUTH)))
                .containsOnly(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN);
    }

    @Test
    void samlYieldsAuthenticatesAndValidatesToken() {
        assertThat(rule.apply(signalsOf(AuthContext.Kind.SAML)))
                .containsOnly(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN);
    }

    @Test
    void principalYieldsAuthenticatesAndUsesIdentity() {
        assertThat(rule.apply(signalsOf(AuthContext.Kind.PRINCIPAL)))
                .containsOnly(CryptoBehavior.AUTHENTICATES, CryptoBehavior.USES_IDENTITY);
    }

    @Test
    void mtlsYieldsAuthenticatesAndUsesIdentity() {
        assertThat(rule.apply(signalsOf(AuthContext.Kind.MTLS)))
                .containsOnly(CryptoBehavior.AUTHENTICATES, CryptoBehavior.USES_IDENTITY);
    }

    @Test
    void apiKeyYieldsAuthenticatesOnly() {
        assertThat(rule.apply(signalsOf(AuthContext.Kind.API_KEY)))
                .containsOnly(CryptoBehavior.AUTHENTICATES);
    }

    @Test
    void noneKindIsNotAPrimary() {
        assertThat(rule.apply(signalsOf(AuthContext.Kind.NONE))).isEmpty();
    }

    @Test
    void noSignalsYieldNothing() {
        assertThat(rule.apply(signalsOf())).isEmpty();
    }

    @Test
    void multipleKindsUnionTheirContributions() {
        assertThat(rule.apply(signalsOf(AuthContext.Kind.JWT, AuthContext.Kind.PRINCIPAL)))
                .containsOnly(
                        CryptoBehavior.AUTHENTICATES,
                        CryptoBehavior.VALIDATES_TOKEN,
                        CryptoBehavior.USES_IDENTITY);
    }

    @Test
    void cryptoBehaviorsInTheSignalsAreIgnored() {
        final BehaviorSignals signals =
                new BehaviorSignals(Set.of(CryptoBehavior.ENCRYPTS_DATA), Set.of());
        assertThat(rule.apply(signals)).isEmpty();
    }
}
```

- [ ] **Step 3: Verify it fails to compile**

Run: `mvn test -pl output -Dtest=AuthInterfaceRuleTest`
Expected: COMPILATION ERROR — `AuthInterfaceRule` does not exist.

- [ ] **Step 4: Implement AuthInterfaceRule**

`output/src/main/java/com/ibm/output/behavior/rules/AuthInterfaceRule.java`:

```java
package com.ibm.output.behavior.rules;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.output.behavior.BehaviorSignals;
import com.ibm.output.behavior.CryptoBehavior;
import com.ibm.output.behavior.IBehaviorRule;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Contributes application-level behaviors from detected auth-interface evidence (design
 * 2026-07-13 §4). Crypto alone never asserts these: a MAC yields only {@code ensuresIntegrity}
 * from the mapper, and {@code authenticates} appears iff an auth interface was observed. SAML
 * validates a signed assertion (a bearer credential), so it also yields {@code validatesToken};
 * PRINCIPAL and MTLS yield {@code usesIdentity} via the authenticated peer principal.
 */
public final class AuthInterfaceRule implements IBehaviorRule {

    // NONE is deliberately absent: it is the "no auth context" marker, never a primary.
    private static final Map<AuthContext.Kind, Set<CryptoBehavior>> CONTRIBUTIONS =
            Map.of(
                    AuthContext.Kind.JWT,
                            Set.of(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN),
                    AuthContext.Kind.OAUTH,
                            Set.of(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN),
                    AuthContext.Kind.SAML,
                            Set.of(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN),
                    AuthContext.Kind.PRINCIPAL,
                            Set.of(CryptoBehavior.AUTHENTICATES, CryptoBehavior.USES_IDENTITY),
                    AuthContext.Kind.MTLS,
                            Set.of(CryptoBehavior.AUTHENTICATES, CryptoBehavior.USES_IDENTITY),
                    AuthContext.Kind.API_KEY, Set.of(CryptoBehavior.AUTHENTICATES));

    @Override
    @Nonnull
    public Set<CryptoBehavior> apply(@Nonnull BehaviorSignals signals) {
        final Set<CryptoBehavior> result = EnumSet.noneOf(CryptoBehavior.class);
        for (AuthContext.Kind kind : signals.authKinds()) {
            result.addAll(CONTRIBUTIONS.getOrDefault(kind, Set.of()));
        }
        return result;
    }
}
```

- [ ] **Step 5: Run and verify pass**

Run: `mvn test -pl output -Dtest=AuthInterfaceRuleTest`
Expected: PASS, 10 tests.

- [ ] **Step 6: Write the failing CryptoBehaviorRule test**

`output/src/test/java/com/ibm/output/behavior/rules/CryptoBehaviorRuleTest.java`:

```java
package com.ibm.output.behavior.rules;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.output.behavior.BehaviorSignals;
import com.ibm.output.behavior.CryptoBehavior;
import java.util.Set;
import org.junit.jupiter.api.Test;

class CryptoBehaviorRuleTest {

    private final CryptoBehaviorRule rule = new CryptoBehaviorRule();

    @Test
    void passesCryptoBehaviorsThroughUnchanged() {
        final BehaviorSignals signals =
                new BehaviorSignals(
                        Set.of(CryptoBehavior.ENCRYPTS_DATA, CryptoBehavior.ENSURES_CONFIDENTIALITY),
                        Set.of(AuthContext.Kind.JWT));
        assertThat(rule.apply(signals))
                .containsOnly(
                        CryptoBehavior.ENCRYPTS_DATA, CryptoBehavior.ENSURES_CONFIDENTIALITY);
    }

    @Test
    void emptySignalsYieldNothing() {
        assertThat(rule.apply(new BehaviorSignals(Set.of(), Set.of()))).isEmpty();
    }
}
```

- [ ] **Step 7: Verify compile failure, then implement CryptoBehaviorRule**

Run: `mvn test -pl output -Dtest=CryptoBehaviorRuleTest`
Expected: COMPILATION ERROR — `CryptoBehaviorRule` does not exist.

`output/src/main/java/com/ibm/output/behavior/rules/CryptoBehaviorRule.java`:

```java
package com.ibm.output.behavior.rules;

import com.ibm.output.behavior.BehaviorSignals;
import com.ibm.output.behavior.CryptoBehavior;
import com.ibm.output.behavior.IBehaviorRule;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Passes the crypto-derived behaviors (the union of {@code CryptoBehaviorMapper} output across
 * all assets) through unchanged. The mapper never derives application-level behaviors, so no
 * gating is needed here.
 */
public final class CryptoBehaviorRule implements IBehaviorRule {

    @Override
    @Nonnull
    public Set<CryptoBehavior> apply(@Nonnull BehaviorSignals signals) {
        return signals.cryptoBehaviors();
    }
}
```

- [ ] **Step 8: Run and verify pass**

Run: `mvn test -pl output -Dtest=CryptoBehaviorRuleTest`
Expected: PASS, 2 tests.

- [ ] **Step 9: Format and commit**

```bash
mvn spotless:apply -pl output -q
git status   # restore JsonCipherSuites*.java if touched
git add -A output
git commit -m "Add behavior signal model and inference rules"
```

---

### Task 4: `BehaviorCollector`

The subsystem's single entry point. TDD against real model nodes — this also gives the `ContextualEvidence` → `Kind` parsing its first unit tests.

**Files:**
- Create: `output/src/main/java/com/ibm/output/behavior/BehaviorCollector.java`
- Test: `output/src/test/java/com/ibm/output/behavior/BehaviorCollectorTest.java`

**Interfaces:**
- Consumes: `CryptoBehaviorMapper.map(INode)` (Task 2), `BehaviorSignals`/`IBehaviorRule`/rules (Task 3), `com.ibm.mapper.model.Algorithm`, `com.ibm.mapper.model.ContextualEvidence` (existing).
- Produces (used by Task 5): `class BehaviorCollector` with no-arg ctor, `void observe(@Nonnull INode node)`, `@Nonnull Set<CryptoBehavior> inferBehaviors()`.

- [ ] **Step 1: Write the failing test**

`output/src/test/java/com/ibm/output/behavior/BehaviorCollectorTest.java`:

```java
package com.ibm.output.behavior;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.model.ContextualEvidence;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Collections;
import org.junit.jupiter.api.Test;

class BehaviorCollectorTest {

    private final IBundle bundle = () -> "Test";
    private final DetectionLocation loc =
            new DetectionLocation("test.java", 1, 1, Collections.emptyList(), bundle);
    private final BehaviorCollector collector = new BehaviorCollector();

    @Test
    void macAloneYieldsIntegrityButNotAuthenticates() {
        collector.observe(new HMAC(loc));
        assertThat(collector.inferBehaviors())
                .containsOnly(CryptoBehavior.ENSURES_INTEGRITY);
    }

    @Test
    void macPlusJwtEvidenceAuthenticatesAndValidatesToken() {
        collector.observe(new HMAC(loc));
        collector.observe(new ContextualEvidence("JWT", loc));
        assertThat(collector.inferBehaviors())
                .containsOnly(
                        CryptoBehavior.AUTHENTICATES,
                        CryptoBehavior.VALIDATES_TOKEN,
                        CryptoBehavior.ENSURES_INTEGRITY);
    }

    @Test
    void jwtEvidenceAloneYieldsTokenBehaviors() {
        collector.observe(new ContextualEvidence("JWT", loc));
        assertThat(collector.inferBehaviors())
                .containsOnly(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN);
    }

    @Test
    void unknownEvidenceIdentifierIsIgnored() {
        collector.observe(new ContextualEvidence("NOT_A_KIND", loc));
        assertThat(collector.inferBehaviors()).isEmpty();
    }

    @Test
    void noneKindEvidenceIsNotAPrimary() {
        collector.observe(new ContextualEvidence("NONE", loc));
        assertThat(collector.inferBehaviors()).isEmpty();
    }

    @Test
    void nonAssetNodesAreIgnored() {
        collector.observe(new Encrypt(loc));
        assertThat(collector.inferBehaviors()).isEmpty();
    }

    @Test
    void cryptoOnlyPassesThrough() {
        final AES aes = new AES(loc);
        aes.put(new Encrypt(loc));
        collector.observe(aes);
        assertThat(collector.inferBehaviors())
                .containsOnly(
                        CryptoBehavior.ENCRYPTS_DATA, CryptoBehavior.ENSURES_CONFIDENTIALITY);
    }
}
```

- [ ] **Step 2: Verify compile failure**

Run: `mvn test -pl output -Dtest=BehaviorCollectorTest`
Expected: COMPILATION ERROR — `BehaviorCollector` does not exist.

- [ ] **Step 3: Implement BehaviorCollector**

`output/src/main/java/com/ibm/output/behavior/BehaviorCollector.java`:

```java
package com.ibm.output.behavior;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.ContextualEvidence;
import com.ibm.mapper.model.INode;
import com.ibm.output.behavior.rules.AuthInterfaceRule;
import com.ibm.output.behavior.rules.CryptoBehaviorRule;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * The output layer's single entry point to the behavior subsystem. Feed every processed node to
 * {@link #observe(INode)} during collection; call {@link #inferBehaviors()} once at emission time
 * to run the rule registry over the collected {@link BehaviorSignals}. Total: unrecognized nodes
 * and identifiers are ignored, never errors.
 */
public final class BehaviorCollector {

    private static final List<IBehaviorRule> RULES =
            List.of(new CryptoBehaviorRule(), new AuthInterfaceRule());

    @Nonnull private final CryptoBehaviorMapper mapper = new CryptoBehaviorMapper();

    @Nonnull
    private final Set<CryptoBehavior> cryptoBehaviors = EnumSet.noneOf(CryptoBehavior.class);

    @Nonnull
    private final Set<AuthContext.Kind> authKinds = EnumSet.noneOf(AuthContext.Kind.class);

    public void observe(@Nonnull INode node) {
        if (node instanceof Algorithm) {
            this.cryptoBehaviors.addAll(this.mapper.map(node));
        } else if (node instanceof ContextualEvidence evidence) {
            // ContextualEvidence carries a generic identifier; only the ones naming an
            // auth-interface kind are behavior signals. Unknown identifiers are skipped.
            try {
                this.authKinds.add(AuthContext.Kind.valueOf(evidence.identifier()));
            } catch (IllegalArgumentException ignored) {
                // not an auth-interface evidence identifier we model
            }
        }
    }

    @Nonnull
    public Set<CryptoBehavior> inferBehaviors() {
        final BehaviorSignals signals = new BehaviorSignals(this.cryptoBehaviors, this.authKinds);
        final Set<CryptoBehavior> result = EnumSet.noneOf(CryptoBehavior.class);
        for (IBehaviorRule rule : RULES) {
            result.addAll(rule.apply(signals));
        }
        return result;
    }
}
```

- [ ] **Step 4: Run and verify pass**

Run: `mvn test -pl output -Dtest=BehaviorCollectorTest`
Expected: PASS, 7 tests.

- [ ] **Step 5: Format and commit**

```bash
mvn spotless:apply -pl output -q
git status   # restore JsonCipherSuites*.java if touched
git add -A output
git commit -m "Add BehaviorCollector as the behavior subsystem entry point"
```

---

### Task 5: Wire `CBOMOutputFile` to the collector, add `BehaviorMetadataWriter`, delete `BehaviorInferenceEngine`

The emitted CBOM must not change — `CryptoBehaviorMetadataTest`'s assertions are untouched and prove it.

**Files:**
- Create: `output/src/main/java/com/ibm/output/cyclondx/BehaviorMetadataWriter.java`
- Modify: `output/src/main/java/com/ibm/output/cyclondx/CBOMOutputFile.java`
- Modify: `output/src/main/java/com/ibm/output/behavior/CryptoBehaviorMapper.java` (remove `BEHAVIOR_PROPERTY_NAME`)
- Modify: `output/src/test/java/com/ibm/output/cyclonedx/CryptoBehaviorMetadataTest.java` (import + constant reference only)
- Delete: `output/src/main/java/com/ibm/output/cyclondx/behavior/BehaviorInferenceEngine.java` (empties the old package)
- Delete: `output/src/test/java/com/ibm/output/cyclonedx/behavior/BehaviorInferenceEngineTest.java` (scenarios live on in `AuthInterfaceRuleTest`/`BehaviorCollectorTest`)

**Interfaces:**
- Consumes: `BehaviorCollector.observe(INode)` / `inferBehaviors()` (Task 4).
- Produces: `BehaviorMetadataWriter.BEHAVIOR_PROPERTY_NAME` (public constant, value `"cbomkit:crypto:behavior"`), `static void attachIfPresent(@Nonnull Metadata metadata, @Nonnull Set<CryptoBehavior> behaviors)`.

- [ ] **Step 1: Point the metadata test at the writer's constant (failing)**

In `CryptoBehaviorMetadataTest.java`:

```java
// old import
import com.ibm.output.behavior.CryptoBehaviorMapper;
// new import
import com.ibm.output.cyclondx.BehaviorMetadataWriter;
```

```java
// old assertion line
assertThat(property.getName()).isEqualTo(CryptoBehaviorMapper.BEHAVIOR_PROPERTY_NAME);
// new assertion line
assertThat(property.getName()).isEqualTo(BehaviorMetadataWriter.BEHAVIOR_PROPERTY_NAME);
```

Run: `mvn test -pl output -Dtest=CryptoBehaviorMetadataTest`
Expected: COMPILATION ERROR — `BehaviorMetadataWriter` does not exist.

- [ ] **Step 2: Create BehaviorMetadataWriter**

`output/src/main/java/com/ibm/output/cyclondx/BehaviorMetadataWriter.java`:

```java
package com.ibm.output.cyclondx;

import com.ibm.output.behavior.CryptoBehavior;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.Property;

/**
 * Experimental: serializes the scan-wide crypto behavior summary as one namespaced property on a
 * synthetic {@code metadata.component}. The only CycloneDX-specific part of the behavior
 * subsystem — inference lives in {@code com.ibm.output.behavior}.
 */
public final class BehaviorMetadataWriter {

    public static final String BEHAVIOR_PROPERTY_NAME = "cbomkit:crypto:behavior";

    // Intentional simplification of spec §4.4: use a fixed name because no scanned-software
    // name is plumbed into getBom(); the ideal value would be the scanned project name.
    private static final String METADATA_COMPONENT_NAME = "application";

    private BehaviorMetadataWriter() {}

    /** Attaches the behavior property to {@code metadata.component}; no-op when empty. */
    public static void attachIfPresent(
            @Nonnull Metadata metadata, @Nonnull Set<CryptoBehavior> behaviors) {
        if (behaviors.isEmpty()) {
            return;
        }
        final Component softwareComponent = new Component();
        softwareComponent.setType(Component.Type.APPLICATION);
        softwareComponent.setName(METADATA_COMPONENT_NAME);
        final String value =
                behaviors.stream()
                        .map(CryptoBehavior::fullId)
                        .sorted()
                        .collect(Collectors.joining(","));
        final Property behaviorProperty = new Property();
        behaviorProperty.setName(BEHAVIOR_PROPERTY_NAME);
        behaviorProperty.setValue(value);
        softwareComponent.setProperties(List.of(behaviorProperty));
        metadata.setComponent(softwareComponent);
    }
}
```

- [ ] **Step 3: Rewire CBOMOutputFile**

All edits in `output/src/main/java/com/ibm/output/cyclondx/CBOMOutputFile.java`:

**3a — fields.** Replace the four behavior fields and the `METADATA_COMPONENT_NAME` constant (currently lines 111-123, between the `dependencies` field and the constructor) with a single field:

```java
    @Nonnull private final BehaviorCollector behaviorCollector = new BehaviorCollector();
```

**3b — add() dispatch.** Replace the `ContextualEvidence` branch:

```java
// old
                    } else if (node instanceof ContextualEvidence evidence) {
                        recordContextualEvidence(evidence);
// new
                    } else if (node instanceof ContextualEvidence evidence) {
                        this.behaviorCollector.observe(evidence);
```

**3c — delete the whole `recordContextualEvidence` method** (the parsing moved into the collector in Task 4).

**3d — createAlgorithmComponent().** Replace the accumulation line and its comment:

```java
// old
        // Accumulate behaviors here so every algorithm path is covered: top-level via add(),
        // nested recursion, and protocol/cipher-suite constituents via direct calls.
        this.aggregatedBehaviors.addAll(this.behaviorMapper.map(node));
// new
        // Observe here so every algorithm path is covered: top-level via add(), nested
        // recursion, and protocol/cipher-suite constituents via direct calls.
        this.behaviorCollector.observe(node);
```

**3e — getBom().** Replace the whole behavior block (from the `// Experimental: attach...` comment through the closing brace of `if (!behaviors.isEmpty()) {...}`, currently lines 373-390) with:

```java
        // Experimental: attach the scan-wide crypto behavior summary to metadata.component.
        BehaviorMetadataWriter.attachIfPresent(
                metadata, this.behaviorCollector.inferBehaviors());
```

**3f — imports.** Remove (all now unused — verify each has no other use before deleting):

```java
import com.ibm.engine.model.context.AuthContext;
import com.ibm.output.behavior.CryptoBehavior;
import com.ibm.output.behavior.CryptoBehaviorMapper;
import com.ibm.output.cyclondx.behavior.BehaviorInferenceEngine;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.cyclonedx.model.Property;
```

Add:

```java
import com.ibm.output.behavior.BehaviorCollector;
```

(`BehaviorMetadataWriter` is same-package — no import.)

- [ ] **Step 4: Delete the engine, its test, and the mapper's constant**

```bash
git rm output/src/main/java/com/ibm/output/cyclondx/behavior/BehaviorInferenceEngine.java
git rm output/src/test/java/com/ibm/output/cyclonedx/behavior/BehaviorInferenceEngineTest.java
```

In `output/src/main/java/com/ibm/output/behavior/CryptoBehaviorMapper.java`, delete the line (the writer owns the name now):

```java
    public static final String BEHAVIOR_PROPERTY_NAME = "cbomkit:crypto:behavior";
```

Confirm the old directories are now empty (no stray files):

```bash
ls output/src/main/java/com/ibm/output/cyclondx/behavior/ 2>/dev/null
ls output/src/test/java/com/ibm/output/cyclonedx/behavior/ 2>/dev/null
```

Expected: both report no such directory (git removes empty dirs) or list nothing.

- [ ] **Step 5: Run the full output module**

Run: `mvn test -pl output`
Expected: BUILD SUCCESS. `CryptoBehaviorMetadataTest` passes with unchanged assertions — the emitted CBOM is identical.

- [ ] **Step 6: Format and commit**

```bash
mvn spotless:apply -pl output -q
git status   # restore JsonCipherSuites*.java if touched
git add -A output
git commit -m "Wire BehaviorCollector into CBOMOutputFile and delete BehaviorInferenceEngine"
```

---

### Task 6: Full verification

**Files:** none (verification only; commit only if formatting produced diffs).

**Interfaces:** n/a.

- [ ] **Step 1: Full output-module test run + style gates**

```bash
mvn test -pl output
mvn checkstyle:check -pl output
mvn spotless:check -pl output
```

Expected: all three BUILD SUCCESS.

- [ ] **Step 2: Whole-project compile (plugin module depends on output)**

Run: `mvn clean package -DskipTests -q`
Expected: BUILD SUCCESS.

- [ ] **Step 3: Confirm no behavior references escaped the refactor**

```bash
grep -rn "cyclondx.behavior\|BehaviorInferenceEngine\|aggregatedBehaviors\|recordContextualEvidence" --include="*.java" output/ java/ python/ engine/ mapper/ | grep -v target
```

Expected: no output.

- [ ] **Step 4: Commit any leftover formatting diffs**

```bash
git status
# only if formatting changed files (after restoring JsonCipherSuites*.java if touched):
git add -A && git commit -m "Apply formatting after behavior subsystem refactor"
```
