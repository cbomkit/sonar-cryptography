# Rule-Graph Memoization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut the BouncyCastle detection-rule graph from ~521k distinct rule objects to the low tens of thousands by memoizing the no-arg `rules()`/`all()` accessors, so the SonarScanner Engine no longer OOMs during rule construction.

**Architecture:** Introduce one thread-safe memoizing `Supplier` helper. Every no-arg `rules()`/`all()` in the `bc/**` rule classes returns a cached, immutable, build-once snapshot instead of re-materializing its whole dependent subtree at each embed site. The parameterized `rules(IDetectionContext)`/`all(IDetectionContext)` overloads null-short-circuit into the same memo so composed no-arg subtrees are shared by reference. Detection behavior is unchanged because rules are immutable `record`s, `match()` builds fresh per-call state, and all traversal state lives in `DetectionStore` (not on rule objects).

**Tech Stack:** Java 17, Maven (multi-module), JUnit 5 + AssertJ, SonarQube plugin API, Google Java Format (AOSP) via Spotless.

## Global Constraints

- **Java version:** Java 17 (module `<release>17</release>`).
- **Formatting:** Google Java Format AOSP style via Spotless — run `mvn -pl java spotless:apply` before every commit; `mvn -pl java spotless:check` must pass.
- **License header:** every new `.java` file needs the Apache 2.0 header (Spotless applies it automatically on `spotless:apply`).
- **Checkstyle:** no unused imports; `@Override` required; private utility constructors; camelCase lambda params.
- **Behavior invariant:** all existing tests in the `java` module must remain green after every task — they are the guard that memoization does not change detection results.
- **Scope:** modify only `java/src/main/java/com/ibm/plugin/rules/detection/bc/**` (plus the new helper + tests). Do **not** touch JCA/SSL/random rule classes, the `engine` builders, or the parameterized-overload *build logic*.
- **Working directory:** worktree `../sonar-cryptography-issue476`, branch `fix/476-rule-graph-memoization`.

---

## Transformation Recipe (shared reference for Tasks 2–8)

Two shapes occur. Every `bc/**` class matches exactly one shape per accessor.

### Imports to add in every modified class
```java
import com.ibm.plugin.rules.detection.Memoize;
import java.util.function.Supplier;
```
(Spotless will sort/dedupe imports on `spotless:apply`.)

### Shape A — no-arg accessor only (no `IDetectionContext` overload)

The class has exactly:
```java
@Nonnull
public static List<IDetectionRule<Tree>> rules() {
    return <EXPR>;              // <EXPR> is e.g. Stream.of(...).flatMap(...).toList()
}
```
Transform to (keep `<EXPR>` byte-for-byte, only wrap it):
```java
private static final Supplier<List<IDetectionRule<Tree>>> RULES =
        Memoize.of(() -> <EXPR>);

@Nonnull
public static List<IDetectionRule<Tree>> rules() {
    return RULES.get();
}
```

### Shape B — no-arg accessor **plus** a `(@Nullable IDetectionContext)` overload

The class has:
```java
@Nonnull
public static List<IDetectionRule<Tree>> rules() {
    return rules(null);
}

@Nonnull
public static List<IDetectionRule<Tree>> rules(@Nullable IDetectionContext ctx) {
    return <BUILD_EXPR>;        // uses ctx
}
```
Transform to (rename the build body into a private `buildRules`, memoize `buildRules(null)`, and short-circuit the overload):
```java
private static final Supplier<List<IDetectionRule<Tree>>> RULES =
        Memoize.of(() -> buildRules(null));

@Nonnull
public static List<IDetectionRule<Tree>> rules() {
    return RULES.get();
}

@Nonnull
public static List<IDetectionRule<Tree>> rules(@Nullable IDetectionContext ctx) {
    return ctx == null ? RULES.get() : buildRules(ctx);
}

@Nonnull
private static List<IDetectionRule<Tree>> buildRules(@Nullable IDetectionContext ctx) {
    return <BUILD_EXPR>;
}
```
For a class that also has `all()`/`all(ctx)`, apply the same pattern with an `ALL`
supplier and a private `buildAll(ctx)`.

**Why the private `buildRules` matters:** the memo lambda must call the private
builder, never the public `rules(null)` — otherwise `rules() → RULES.get() →
buildRules? ` would instead recurse `rules() → rules(null) → rules()` forever.
The `ctx == null` short-circuit means any caller doing `X.rules(null)` /
`X.all(null)` (e.g. `BcBlockCipher.buildAll(null)` calling
`BcBlockCipherEngine.rules(null)`) reuses the child's memo, so composed subtrees
are shared without per-call-site rewiring.

### Per-task verification (Tasks 2–8)
After editing a task's files:
```bash
cd ../sonar-cryptography-issue476
mvn -pl java -am spotless:apply -q
mvn -pl java -am compile -q            # must succeed
mvn -pl java test -q                   # existing rule tests must stay green
```

---

### Task 1: `Memoize` helper

**Files:**
- Create: `java/src/main/java/com/ibm/plugin/rules/detection/Memoize.java`
- Test: `java/src/test/java/com/ibm/plugin/rules/detection/MemoizeTest.java`

**Interfaces:**
- Produces: `com.ibm.plugin.rules.detection.Memoize.of(Supplier<List<IDetectionRule<Tree>>>) -> Supplier<List<IDetectionRule<Tree>>>` — returns a thread-safe supplier that invokes the delegate at most once and caches `List.copyOf(...)` of its result.

- [ ] **Step 1: Write the failing test**

Create `java/src/test/java/com/ibm/plugin/rules/detection/MemoizeTest.java`:
```java
/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.plugin.rules.detection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ibm.engine.rule.IDetectionRule;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.java.api.tree.Tree;

class MemoizeTest {

    @Test
    void buildsOnceAndCaches() {
        AtomicInteger calls = new AtomicInteger();
        Supplier<List<IDetectionRule<Tree>>> memo =
                Memoize.of(
                        () -> {
                            calls.incrementAndGet();
                            return new ArrayList<>();
                        });

        List<IDetectionRule<Tree>> first = memo.get();
        List<IDetectionRule<Tree>> second = memo.get();

        assertThat(calls.get()).isEqualTo(1);
        assertThat(second).isSameAs(first);
    }

    @Test
    void returnsImmutableSnapshot() {
        List<IDetectionRule<Tree>> backing = new ArrayList<>();
        Supplier<List<IDetectionRule<Tree>>> memo = Memoize.of(() -> backing);

        List<IDetectionRule<Tree>> result = memo.get();

        assertThatThrownBy(() -> result.add(null))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ../sonar-cryptography-issue476 && mvn -pl java -am test -q -Dtest=MemoizeTest`
Expected: FAIL / compile error — `Memoize` does not exist yet.

- [ ] **Step 3: Write minimal implementation**

Create `java/src/main/java/com/ibm/plugin/rules/detection/Memoize.java`:
```java
/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.plugin.rules.detection;

import com.ibm.engine.rule.IDetectionRule;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

/**
 * Lazily builds and caches a rule list so that shared detection-rule subtrees are constructed once
 * and referenced everywhere, instead of being re-materialized at every embed site. The cached value
 * is an immutable snapshot ({@link List#copyOf}); the delegate runs at most once.
 */
public final class Memoize {

    private Memoize() {
        // utility
    }

    @Nonnull
    public static Supplier<List<IDetectionRule<Tree>>> of(
            @Nonnull Supplier<List<IDetectionRule<Tree>>> delegate) {
        return new Supplier<>() {
            private volatile List<IDetectionRule<Tree>> value;

            @Override
            public List<IDetectionRule<Tree>> get() {
                List<IDetectionRule<Tree>> snapshot = value;
                if (snapshot == null) {
                    synchronized (this) {
                        snapshot = value;
                        if (snapshot == null) {
                            snapshot = List.copyOf(delegate.get());
                            value = snapshot;
                        }
                    }
                }
                return snapshot;
            }
        };
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -pl java -am test -q -Dtest=MemoizeTest`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
cd ../sonar-cryptography-issue476
mvn -pl java spotless:apply -q
git add java/src/main/java/com/ibm/plugin/rules/detection/Memoize.java \
        java/src/test/java/com/ibm/plugin/rules/detection/MemoizeTest.java
git commit -m "feat(java): add Memoize helper for rule-graph memoization (#476)"
```

---

### Task 2: Memoize the block-cipher diamond (`BcBlockCipherEngine`, `BcBlockCipher`)

These are the central shared nodes. Both are **Shape B**. `BcBlockCipher` has
both `rules` and `all`.

**Files:**
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/bc/blockcipher/BcBlockCipherEngine.java`
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/bc/blockcipher/BcBlockCipher.java`

**Interfaces:**
- Consumes: `Memoize.of(...)` from Task 1.
- Produces: memoized `BcBlockCipherEngine.rules()`, `BcBlockCipher.rules()`, `BcBlockCipher.all()` (same signatures as today).

- [ ] **Step 1: Edit `BcBlockCipherEngine`**

Add imports `com.ibm.plugin.rules.detection.Memoize` and `java.util.function.Supplier`. Replace the existing accessor block:
```java
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return rules(null);
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules(
            @Nullable IDetectionContext detectionValueContext) {
        return simpleConstructors(detectionValueContext);
    }
```
with:
```java
    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(() -> simpleConstructors(null));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules(
            @Nullable IDetectionContext detectionValueContext) {
        return detectionValueContext == null
                ? RULES.get()
                : simpleConstructors(detectionValueContext);
    }
```
(Here `simpleConstructors` already **is** the build method, so no separate `buildRules` is needed.)

- [ ] **Step 2: Edit `BcBlockCipher`**

Add the two imports. Replace the four accessors:
```java
    public static List<IDetectionRule<Tree>> rules() {
        return rules(null);
    }
    ...
    public static List<IDetectionRule<Tree>> all() {
        return all(null);
    }
    ...
    public static List<IDetectionRule<Tree>> rules(
            @Nullable IDetectionContext detectionValueContext) {
        return Stream.of(
                        simpleConstructors(detectionValueContext).stream(),
                        specialConstructors(detectionValueContext).stream())
                .flatMap(i -> i)
                .toList();
    }
    ...
    public static List<IDetectionRule<Tree>> all(
            @Nullable IDetectionContext detectionValueContext) {
        return Stream.of(
                        rules(detectionValueContext).stream(),
                        BcBlockCipherEngine.rules(detectionValueContext).stream())
                .flatMap(i -> i)
                .toList();
    }
```
with:
```java
    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(() -> buildRules(null));
    private static final Supplier<List<IDetectionRule<Tree>>> ALL =
            Memoize.of(() -> buildAll(null));

    @Nonnull
    // Rules defined in this file (classes finishing with BlockCipher)
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    // All BlockCipher rules including all the engines
    public static List<IDetectionRule<Tree>> all() {
        return ALL.get();
    }

    @Nonnull
    // Rules defined in this file (classes finishing with BlockCipher)
    public static List<IDetectionRule<Tree>> rules(
            @Nullable IDetectionContext detectionValueContext) {
        return detectionValueContext == null ? RULES.get() : buildRules(detectionValueContext);
    }

    @Nonnull
    // All BlockCipher rules including all the engines
    public static List<IDetectionRule<Tree>> all(
            @Nullable IDetectionContext detectionValueContext) {
        return detectionValueContext == null ? ALL.get() : buildAll(detectionValueContext);
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules(
            @Nullable IDetectionContext detectionValueContext) {
        return Stream.of(
                        simpleConstructors(detectionValueContext).stream(),
                        specialConstructors(detectionValueContext).stream())
                .flatMap(i -> i)
                .toList();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildAll(
            @Nullable IDetectionContext detectionValueContext) {
        return Stream.of(
                        rules(detectionValueContext).stream(),
                        BcBlockCipherEngine.rules(detectionValueContext).stream())
                .flatMap(i -> i)
                .toList();
    }
```

- [ ] **Step 3: Format, compile, test**

Run:
```bash
cd ../sonar-cryptography-issue476
mvn -pl java -am spotless:apply -q && mvn -pl java -am compile -q && mvn -pl java test -q
```
Expected: BUILD SUCCESS; all existing tests pass (behavior unchanged).

- [ ] **Step 4: Commit**

```bash
git add java/src/main/java/com/ibm/plugin/rules/detection/bc/blockcipher/BcBlockCipherEngine.java \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/blockcipher/BcBlockCipher.java
git commit -m "perf(java): memoize BcBlockCipher/BcBlockCipherEngine rule subtrees (#476)"
```

---

### Task 3: Memoize `BcDigests` (Shape B)

**Files:**
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/bc/digest/BcDigests.java`

**Interfaces:**
- Produces: memoized `BcDigests.rules()`; `BcDigests.rules(ctx)` unchanged for non-null ctx (e.g. MGF1 callers).

- [ ] **Step 1: Edit `BcDigests`**

Add the two imports. Replace:
```java
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return rules(null);
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules(
            @Nullable IDetectionContext detectionValueContext) {
        return Stream.concat(
                        regularConstructors(detectionValueContext).stream(),
                        otherConstructors(detectionValueContext).stream())
                .toList();
    }
```
with:
```java
    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(() -> buildRules(null));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules(
            @Nullable IDetectionContext detectionValueContext) {
        return detectionValueContext == null ? RULES.get() : buildRules(detectionValueContext);
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules(
            @Nullable IDetectionContext detectionValueContext) {
        return Stream.concat(
                        regularConstructors(detectionValueContext).stream(),
                        otherConstructors(detectionValueContext).stream())
                .toList();
    }
```

- [ ] **Step 2: Format, compile, test**

Run: `cd ../sonar-cryptography-issue476 && mvn -pl java -am spotless:apply -q && mvn -pl java -am compile -q && mvn -pl java test -q`
Expected: BUILD SUCCESS; all tests pass.

- [ ] **Step 3: Commit**

```bash
git add java/src/main/java/com/ibm/plugin/rules/detection/bc/digest/BcDigests.java
git commit -m "perf(java): memoize BcDigests rule subtree (#476)"
```

---

### Task 4: Memoize the asymmetric Shape-B classes

Five classes each expose `rules()` + `rules(@Nullable IDetectionContext)`.

**Files:**
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetricblockcipher/BcAsymCipherEngine.java`
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetricblockcipher/BcAsymmetricBlockCipher.java`
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetricblockcipher/BcISO9796d1Encoding.java`
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetricblockcipher/BcOAEPEncoding.java`
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetricblockcipher/BcPKCS1Encoding.java`

- [ ] **Step 1: Apply the Shape-B recipe to each file**

For every file above, add the two imports and transform the accessor pair using the **Shape B** recipe from the Transformation Recipe section:
1. Add `private static final Supplier<List<IDetectionRule<Tree>>> RULES = Memoize.of(() -> buildRules(null));`
2. `rules()` → `return RULES.get();`
3. `rules(@Nullable ctx)` → `return ctx == null ? RULES.get() : buildRules(ctx);` (match each file's actual parameter name, e.g. `detectionValueContext` or `engineDetectionValueContext`).
4. Move the original `rules(ctx)` body verbatim into a new `@Nonnull private static List<IDetectionRule<Tree>> buildRules(@Nullable ... ctx)`.

Do **not** alter the build body (it may call `BcAsymCipherEngine.rules(ctx)` or `BcDigests.rules(new DigestContext(...))` with non-null contexts — those stay as-is and keep building fresh).

- [ ] **Step 2: Format, compile, test**

Run: `cd ../sonar-cryptography-issue476 && mvn -pl java -am spotless:apply -q && mvn -pl java -am compile -q && mvn -pl java test -q`
Expected: BUILD SUCCESS; all tests pass.

- [ ] **Step 3: Commit**

```bash
git add java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetricblockcipher/BcAsymCipherEngine.java \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetricblockcipher/BcAsymmetricBlockCipher.java \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetricblockcipher/BcISO9796d1Encoding.java \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetricblockcipher/BcOAEPEncoding.java \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetricblockcipher/BcPKCS1Encoding.java
git commit -m "perf(java): memoize asymmetric block-cipher rule subtrees (#476)"
```

---

### Task 5: Memoize Shape-A cipher classes (modes, AEAD, stream, buffered, wrapper, inits)

All files below are **Shape A** (single no-arg `rules()`; wrap `<EXPR>` in `Memoize.of`).

**Files:**
- `bc/blockcipher/BcBlockCipherInit.java`
- `bc/aeadcipher/BcAEADCipherEngine.java`, `BcAEADCipherInit.java`, `BcCCMBlockCipher.java`, `BcChaCha20Poly1305.java`, `BcEAXBlockCipher.java`, `BcGCMBlockCipher.java`, `BcGCMSIVBlockCipher.java`, `BcKCCMBlockCipher.java`, `BcKGCMBlockCipher.java`, `BcOCBBlockCipher.java`
- `bc/streamcipher/BcStreamCipherEngine.java`, `BcStreamCipherInit.java`
- `bc/bufferedblockcipher/BcBufferedBlockCipher.java`, `BcBufferedBlockCipherInit.java`
- `bc/blockcipherpadding/BcBlockCipherPadding.java`
- `bc/wrapper/BcWrapperEngine.java`, `BcWrapperInit.java`

(All paths are under `java/src/main/java/com/ibm/plugin/rules/detection/`.)

- [ ] **Step 1: Apply the Shape-A recipe to each file**

For each file: add imports `com.ibm.plugin.rules.detection.Memoize` and `java.util.function.Supplier`, then convert its single no-arg `rules()` from:
```java
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return <EXPR>;
    }
```
to:
```java
    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(() -> <EXPR>);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }
```
where `<EXPR>` is that file's existing return expression, copied unchanged.

Worked example (`BcMac`-style body from another module — same mechanical edit): a
body of `Stream.of(simpleConstructors().stream(), specialConstructors().stream()).flatMap(i -> i).toList()`
becomes `Memoize.of(() -> Stream.of(simpleConstructors().stream(), specialConstructors().stream()).flatMap(i -> i).toList())`.

If any listed file turns out to also have a `(@Nullable IDetectionContext)`
overload (it should not, per the survey), use **Shape B** instead and note it in
the commit.

- [ ] **Step 2: Format, compile, test**

Run: `cd ../sonar-cryptography-issue476 && mvn -pl java -am spotless:apply -q && mvn -pl java -am compile -q && mvn -pl java test -q`
Expected: BUILD SUCCESS; all tests pass.

- [ ] **Step 3: Commit**

```bash
git add java/src/main/java/com/ibm/plugin/rules/detection/bc/blockcipher/BcBlockCipherInit.java \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/aeadcipher/ \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/streamcipher/ \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/bufferedblockcipher/ \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/blockcipherpadding/ \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/wrapper/
git commit -m "perf(java): memoize cipher/AEAD/wrapper rule subtrees (#476)"
```

---

### Task 6: Memoize Shape-A MAC, digest-adjacent, KDF, PBE, agreement, keygen classes

All **Shape A**.

**Files** (under `java/src/main/java/com/ibm/plugin/rules/detection/`):
- `bc/mac/BcMac.java`, `bc/mac/BcMacInit.java`
- `bc/derivationfunction/BcDerivationFunction.java`
- `bc/pbe/BcPBEParametersGenerator.java`
- `bc/basicagreement/BcBasicAgreement.java`, `bc/basicagreement/BcBasicAgreementInit.java`
- `bc/keygenerationparameters/BcKeyGenerationParameters.java`, `bc/keygenerationparameters/BcRSAKeyGenerationParameters.java`

- [ ] **Step 1: Apply the Shape-A recipe to each file** (identical mechanical edit as Task 5, Step 1).

- [ ] **Step 2: Format, compile, test**

Run: `cd ../sonar-cryptography-issue476 && mvn -pl java -am spotless:apply -q && mvn -pl java -am compile -q && mvn -pl java test -q`
Expected: BUILD SUCCESS; all tests pass.

- [ ] **Step 3: Commit**

```bash
git add java/src/main/java/com/ibm/plugin/rules/detection/bc/mac/ \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/derivationfunction/ \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/pbe/ \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/basicagreement/ \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/keygenerationparameters/
git commit -m "perf(java): memoize MAC/KDF/PBE/agreement rule subtrees (#476)"
```

---

### Task 7: Memoize Shape-A `cipherparameters` classes

All 18 files in `bc/cipherparameters/` are **Shape A**.

**Files** (under `java/src/main/java/com/ibm/plugin/rules/detection/bc/cipherparameters/`):
`BcAEADParameters.java`, `BcCCMParameters.java`, `BcCipherParameters.java`,
`BcCramerShoupParameters.java`, `BcGMSSParameters.java`, `BcIESParameters.java`,
`BcKeyParameter.java`, `BcMLDSAKeyParameters.java`, `BcMLDSAPrivateKeyParameters.java`,
`BcMLDSAPublicKeyParameters.java`, `BcMLKEMKeyParameters.java`,
`BcMLKEMPrivateKeyParameters.java`, `BcMLKEMPublicKeyParameters.java`,
`BcNTRUEncryptionParameters.java`, `BcNTRUSigningPrivateKeyParameters.java`,
`BcNTRUSigningPublicKeyParameters.java`, `BcParametersWith.java`, `BcSABERParameters.java`

- [ ] **Step 1: Apply the Shape-A recipe to each file** (identical mechanical edit as Task 5, Step 1).

- [ ] **Step 2: Format, compile, test**

Run: `cd ../sonar-cryptography-issue476 && mvn -pl java -am spotless:apply -q && mvn -pl java -am compile -q && mvn -pl java test -q`
Expected: BUILD SUCCESS; all tests pass.

- [ ] **Step 3: Commit**

```bash
git add java/src/main/java/com/ibm/plugin/rules/detection/bc/cipherparameters/
git commit -m "perf(java): memoize cipher-parameter rule subtrees (#476)"
```

---

### Task 8: Memoize remaining Shape-A classes (signers, DSA, keypair, encapsulated-secret, other, aggregator)

All **Shape A**.

**Files** (under `java/src/main/java/com/ibm/plugin/rules/detection/`):
- `bc/signer/` — all 13: `BcDSADigestSigner.java`, `BcGenericSigner.java`, `BcHashMLDSASigner.java`, `BcISO9796d2PSSSigner.java`, `BcISO9796d2Signer.java`, `BcMLDSASigner.java`, `BcPQCSigner.java`, `BcPSSSigner.java`, `BcRSADigestSigner.java`, `BcSM2Signer.java`, `BcSigner.java`, `BcSignerInit.java`, `BcSimpleSigner.java`, `BcX931Signer.java`
- `bc/messagesigner/` — `BcMessageSigner.java`, `BcMessageSignerInit.java`, `BcStateAwareMessageSigner.java`
- `bc/dsa/` — `BcDSA.java`, `BcDSAInit.java`
- `bc/asymmetrickeypair/` — `BcAsymmetricCipherKeyPairGenerators.java`, `BcRSAKeyPairGenerator.java`, `BcRSAKeyPairGeneratorInit.java`
- `bc/asymmetricblockcipher/` — `BcAsymCipherInit.java`, `BcBufferedAsymmetricBlockCipher.java` (the Shape-A members of that package; the Shape-B ones were done in Task 4)
- `bc/encapsulatedsecret/` — `BcEncapsulatedSecretExtractor.java`, `BcEncapsulatedSecretGenerator.java`, `BcGenerateEncapsulatedSecret.java`
- `bc/other/` — `BcIESEngine.java`, `BcIESEngineInit.java`, `BcSM2Engine.java`, `BcSM2EngineInit.java`
- `bc/BouncyCastleDetectionRules.java`

- [ ] **Step 1: Apply the Shape-A recipe to each file** (identical mechanical edit as Task 5, Step 1). Note `BcSigner.java` has count 14 signer files; `BcSignerInit.java` is included above.

- [ ] **Step 2: Confirm every `bc/**` class is now memoized**

Run:
```bash
cd ../sonar-cryptography-issue476
grep -rL "Memoize.of" $(grep -rlE "public static List<IDetectionRule<Tree>> (rules|all)\(" java/src/main/java/com/ibm/plugin/rules/detection/bc/)
```
Expected: **no output** (every BC rule class references `Memoize.of`). If any file prints, apply the recipe to it before continuing.

- [ ] **Step 3: Format, compile, test**

Run: `mvn -pl java -am spotless:apply -q && mvn -pl java -am compile -q && mvn -pl java test -q`
Expected: BUILD SUCCESS; all tests pass.

- [ ] **Step 4: Commit**

```bash
git add java/src/main/java/com/ibm/plugin/rules/detection/bc/signer/ \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/messagesigner/ \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/dsa/ \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetrickeypair/ \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetricblockcipher/BcAsymCipherInit.java \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetricblockcipher/BcBufferedAsymmetricBlockCipher.java \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/encapsulatedsecret/ \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/other/ \
        java/src/main/java/com/ibm/plugin/rules/detection/bc/BouncyCastleDetectionRules.java
git commit -m "perf(java): memoize signer/DSA/keypair/other rule subtrees (#476)"
```

---

### Task 9: Distinct-object regression test

Now that the whole BC graph is memoized, add the count guard. It walks the full
Java rule graph following both child edges and asserts the distinct-object count
collapsed.

**Files:**
- Test: `java/src/test/java/com/ibm/plugin/rules/RuleGraphMemoizationTest.java`

**Interfaces:**
- Consumes: `com.ibm.plugin.rules.detection.JavaDetectionRules.rules()` (static, `List<IDetectionRule<Tree>>`); `IDetectionRule.nextDetectionRules()`; `DetectionRule.parameters()` → `List<Parameter<T>>`; `Parameter.getDetectionRules()`.

- [ ] **Step 1: Write the test**

Create `java/src/test/java/com/ibm/plugin/rules/RuleGraphMemoizationTest.java`:
```java
/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.plugin.rules;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.Parameter;
import com.ibm.plugin.rules.detection.JavaDetectionRules;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Guards the fix for issue #476: memoization must keep the distinct-object footprint of the Java
 * detection-rule graph far below its pre-fix size (~521k objects). Counts distinct
 * DetectionRule/MethodDetectionRule instances reachable via nextDetectionRules() and
 * parameter-attached depending rules, deduped by object identity.
 */
class RuleGraphMemoizationTest {

    /** Pre-fix distinct-object count was ~521,017; memoization targets the low tens of thousands. */
    private static final int MAX_DISTINCT_RULES = 60_000;

    @Test
    void distinctRuleObjectFootprintStaysSmall() {
        Set<IDetectionRule<?>> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        Deque<IDetectionRule<?>> stack = new ArrayDeque<>(JavaDetectionRules.rules());

        while (!stack.isEmpty()) {
            IDetectionRule<?> rule = stack.pop();
            if (!seen.add(rule)) {
                continue;
            }
            stack.addAll(rule.nextDetectionRules());
            if (rule instanceof DetectionRule<?> detectionRule) {
                for (Parameter<?> parameter : detectionRule.parameters()) {
                    stack.addAll(parameter.getDetectionRules());
                }
            }
        }

        System.out.println("[#476] distinct reachable rule objects = " + seen.size());
        assertThat(seen.size()).isLessThan(MAX_DISTINCT_RULES);
    }
}
```

- [ ] **Step 2: Run the test and capture the count**

Run: `cd ../sonar-cryptography-issue476 && mvn -pl java -am test -q -Dtest=RuleGraphMemoizationTest`
Expected: PASS. Note the printed `[#476] distinct reachable rule objects = N`.

- [ ] **Step 3: Verify the ≥10× acceptance target and tighten the threshold**

The pre-fix count was ~521,017; acceptance requires ≥10× reduction (i.e. `N < 52_101`).
- If `N < 52_101`: the `60_000` bound already passes and holds headroom — leave it, but record `N` in the commit message.
- If `52_101 <= N < 60_000`: the memory win landed but the ≥10× bar was missed — this should not happen with full BC memoization; re-run Task 8 Step 2's `grep -rL` check to find an un-memoized hot node, fix it, and re-measure.

- [ ] **Step 4: Commit**

```bash
git add java/src/test/java/com/ibm/plugin/rules/RuleGraphMemoizationTest.java
git commit -m "test(java): guard rule-graph distinct-object footprint (#476), N=<count>"
```

---

### Task 10: Full verification and documentation note

**Files:**
- Modify (optional): `docs/TROUBLESHOOTING.md` — annotate the `-Xmx` workaround as no longer required by default.

- [ ] **Step 1: Full module build with formatting + style gates**

Run:
```bash
cd ../sonar-cryptography-issue476
mvn -pl java -am spotless:check checkstyle:check -q
mvn -pl java -am test -q
```
Expected: BUILD SUCCESS; Spotless and Checkstyle clean; entire `java` module test suite green (including `MemoizeTest` and `RuleGraphMemoizationTest`).

- [ ] **Step 2: Full project build (catches cross-module fallout)**

Run: `mvn clean package -q`
Expected: BUILD SUCCESS across all modules.

- [ ] **Step 3: Update the troubleshooting note (if the `-Xmx` workaround section exists)**

In `docs/TROUBLESHOOTING.md`, add one line to the Scanner Engine heap / rule-graph OOM section:
```markdown
> As of the fix for #476, the default Scanner Engine heap is sufficient for a
> representative scan; the `-Dsonar.scanner.javaOpts=-Xmx2g` workaround below is
> retained only as a fallback for unusually constrained environments.
```
If no such section exists, skip this step.

- [ ] **Step 4: Commit any doc change and push the branch**

```bash
cd ../sonar-cryptography-issue476
git add docs/TROUBLESHOOTING.md 2>/dev/null || true
git commit -m "docs: note #476 fix reduces default-heap requirement" 2>/dev/null || true
git push -u origin fix/476-rule-graph-memoization
```

- [ ] **Step 5: Open the PR (optional, when ready)**

```bash
gh pr create --fill --base main \
  --title "perf(java): memoize BouncyCastle rule graph to cut construction heap (#476)" \
  --body "Closes #476. Memoizes no-arg rules()/all() across bc/** so shared subtrees are built once. Distinct rule objects reduced from ~521k to <count> (>=10x). Existing rule tests unchanged; adds MemoizeTest + RuleGraphMemoizationTest."
```

---

## Self-Review

**Spec coverage:**
- Memoize no-arg default-context variants across BC classes → Tasks 2–8 (all `bc/**`), verified by Task 8 Step 2.
- Leave parameterized `(IDetectionContext)` overloads building fresh → Shape-B recipe keeps `buildRules(ctx)` for non-null ctx; JCA/SSL/random untouched.
- Immutable-snapshot sharing → `Memoize.of` caches `List.copyOf(...)`, tested in Task 1.
- Committed distinct-object regression test following `nextDetectionRules()` + `Parameter.getDetectionRules()` with identity dedup and a threshold → Task 9.
- Behavior preserved → existing suite run every task; full build in Task 10.
- ≥10× acceptance + default-heap claim → Task 9 Step 3 + Task 10 Steps 2–3.

**Placeholder scan:** No `TBD`/`TODO`; the only `<...>` tokens (`<EXPR>`, `<BUILD_EXPR>`, `<count>`) are explicit copy-the-existing-expression / fill-the-measured-number instructions with worked examples, not deferred work.

**Type consistency:** `Memoize.of(Supplier<List<IDetectionRule<Tree>>>) -> Supplier<List<IDetectionRule<Tree>>>` used identically in Tasks 1–8; test uses confirmed accessors `JavaDetectionRules.rules()` (static), `IDetectionRule.nextDetectionRules()`, `DetectionRule.parameters()`, `Parameter.getDetectionRules()`.
