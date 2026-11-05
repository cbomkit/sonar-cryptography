# CycloneDX Algorithm-Name Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the algorithm classes in `mapper/src/main/java/com/ibm/mapper/model` emit names that conform to the CycloneDX cryptography algorithm pattern format, and update all tests/fixtures to match.

**Architecture:** Rename base `NAME` constants and add/fix `asString()` composition so each schema-named class resolves to a valid pattern instance (e.g. `AES-256-CBC`, `CAST5-128`, `CMAC-AES`). A shared `Algorithm.composeName(...)` helper removes the per-class duplication. A new mapper unit test (`AlgorithmNameCompositionTest`) is the authoritative source of truth for target names; the ~130 downstream fixture assertions across java/python/go are then mechanically updated from deterministic test output.

**Tech Stack:** Java 17, Maven (multi-module), JUnit 5 + AssertJ, Google Java Format (Spotless, AOSP), Checkstyle.

## Global Constraints

- **Scope:** only the schema-named classes in the spec's Section 6 mapping table. Do **not** rename or add composition to out-of-scope classes (GOST family, `DESede`, BC lightweight-crypto candidates, pre-standard PQC, etc.). Full list: spec Section 3.
- **Composition rule:** compose exactly the parameters the schema pattern lists, in pattern order, and no others (spec Section 2.1). IV length / tag length are out of scope even where a pattern lists them.
- **Do not** change the return value of `KeyLength`/`DigestSize`/`TagLength`.`asString()` (they stay bare numbers); separators are added at the algorithm-composition site.
- **Tests:** never weaken an assertion or delete a test to make it pass. Every changed expected value must correspond to a Section 6 rename/composition rule.
- **Before every commit:** `mvn spotless:apply` then `mvn checkstyle:check` must succeed. Apache license headers and `@Override` annotations preserved; update JavaDoc where a `NAME` changes.
- **Reference:** spec at `docs/superpowers/specs/2026-07-03-cyclonedx-algorithm-naming-migration-design.md`.
- **DetectionLocation for tests:** `new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "TEST")`.

---

### Task 1: Shared composition helper + unit-test scaffold

**Files:**
- Modify: `mapper/src/main/java/com/ibm/mapper/model/Algorithm.java` (add `composeName`)
- Test: `mapper/src/test/java/com/ibm/mapper/model/algorithms/AlgorithmNameCompositionTest.java` (create)

**Interfaces:**
- Produces: `protected @Nonnull String Algorithm.composeName(boolean keyLength, boolean mode, boolean padding)` — used by all block-cipher tasks (3, 4, 5).

- [ ] **Step 1: Write the failing test**

Create `mapper/src/test/java/com/ibm/mapper/model/algorithms/AlgorithmNameCompositionTest.java`:

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
package com.ibm.mapper.model.algorithms;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class AlgorithmNameCompositionTest {

    static final DetectionLocation TEST =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "TEST");

    @Test
    void aesComposesKeyLengthAndModeWithHyphens() {
        Mode cbc = new CBC(TEST);
        AES aes = new AES(256, cbc, TEST);
        assertThat(aes.asString()).isEqualTo("AES-256-CBC");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest`
Expected: FAIL — actual is `AES256-CBC` (missing hyphen before key length).

- [ ] **Step 3: Add the `composeName` helper**

In `Algorithm.java`, add imports if missing (`com.ibm.mapper.model.KeyLength`, `Mode`, `Padding` are in the same package `com.ibm.mapper.model`, so no import needed) and insert after the existing `asString()` method (around line 100):

```java
    /**
     * Composes this algorithm's name as {@code base[-keyLength][-mode][-padding]} following the
     * CycloneDX pattern format (https://cyclonedx.org/registry/cryptography/#pattern-format). Only
     * the parameters flagged {@code true} — and only when present as children — are appended.
     */
    @Nonnull
    protected String composeName(boolean keyLength, boolean mode, boolean padding) {
        final StringBuilder sb = new StringBuilder(this.name);
        if (keyLength) {
            this.hasChildOfType(KeyLength.class)
                    .ifPresent(k -> sb.append("-").append(k.asString()));
        }
        if (mode) {
            this.hasChildOfType(Mode.class).ifPresent(m -> sb.append("-").append(m.asString()));
        }
        if (padding) {
            this.hasChildOfType(Padding.class)
                    .ifPresent(p -> sb.append("-").append(p.asString()));
        }
        return sb.toString();
    }
```

- [ ] **Step 4: Wire AES to the helper**

In `algorithms/AES.java`, replace the body of `asString()` with:

```java
    @Override
    public @Nonnull String asString() {
        return composeName(true, true, true);
    }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest`
Expected: PASS.

- [ ] **Step 6: Format, style, commit**

```bash
cd /Users/nko/_project/sonar-cryptography
mvn spotless:apply -q && mvn checkstyle:check -q -pl mapper
git add mapper/src/main/java/com/ibm/mapper/model/Algorithm.java \
        mapper/src/main/java/com/ibm/mapper/model/algorithms/AES.java \
        mapper/src/test/java/com/ibm/mapper/model/algorithms/AlgorithmNameCompositionTest.java
git commit -m "Add composeName helper and wire AES; scaffold composition test"
```

---

### Task 2: SHA3 correction (SHA-3 → SHA3)

**Files:**
- Modify: `mapper/src/main/java/com/ibm/mapper/model/algorithms/SHA3.java`
- Test: `AlgorithmNameCompositionTest.java`

**Interfaces:**
- Consumes: nothing new.
- Produces: `new SHA3(256, loc).asString()` == `"SHA3-256"`.

- [ ] **Step 1: Add the failing test**

Append to `AlgorithmNameCompositionTest` (and add `import com.ibm.mapper.model.algorithms.SHA3;`):

```java
    @Test
    void sha3UsesSchemaTokenWithoutHyphenAfterSha() {
        SHA3 sha3 = new SHA3(256, TEST);
        assertThat(sha3.asString()).isEqualTo("SHA3-256");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#sha3UsesSchemaTokenWithoutHyphenAfterSha`
Expected: FAIL — actual `SHA-3-256`.

- [ ] **Step 3: Fix `NAME` and JavaDoc in `SHA3.java`**

Change:

```java
    private static final String NAME = "SHA-3";
```
to:
```java
    private static final String NAME = "SHA3";
```

And fix the misquoted JavaDoc line to state the real pattern:

```java
 *   <li>https://cyclonedx.org/schema/cryptography-defs.json (pattern: SHA3-(224|256|384|512))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#sha3UsesSchemaTokenWithoutHyphenAfterSha`
Expected: PASS.

- [ ] **Step 5: Format, style, commit**

```bash
mvn spotless:apply -q && mvn checkstyle:check -q -pl mapper
git add mapper/src/main/java/com/ibm/mapper/model/algorithms/SHA3.java \
        mapper/src/test/java/com/ibm/mapper/model/algorithms/AlgorithmNameCompositionTest.java
git commit -m "Correct SHA3 name to match CycloneDX pattern (SHA3-256)"
```

---

### Task 3: DES composition — hyphen + drop padding

**Files:**
- Modify: `mapper/src/main/java/com/ibm/mapper/model/algorithms/DES.java`
- Test: `AlgorithmNameCompositionTest.java`

**Interfaces:**
- Consumes: `Algorithm.composeName` (Task 1).
- Produces: `new DES(56, new CBC(loc), loc).asString()` == `"DES-56-CBC"` (no padding component).

- [ ] **Step 1: Add the failing test**

Append (add `import com.ibm.mapper.model.algorithms.DES;`, `import com.ibm.mapper.model.Padding;`, `import com.ibm.mapper.model.padding.PKCS5;`):

```java
    @Test
    void desComposesKeyLengthAndModeButNotPadding() {
        Mode cbc = new CBC(TEST);
        Padding pkcs5 = new PKCS5(TEST);
        DES des = new DES(56, cbc, pkcs5, TEST);
        assertThat(des.asString()).isEqualTo("DES-56-CBC");
    }
```

> If `DES` has no `(int, Mode, Padding, DetectionLocation)` constructor, build it with the available constructor and `put(...)` the padding, mirroring the class's existing constructors. Verify the constructor list in `DES.java` first.

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#desComposesKeyLengthAndModeButNotPadding`
Expected: FAIL — actual `DES56-CBC-PKCS5` (no hyphen before key length, padding wrongly appended).

- [ ] **Step 3: Replace `DES.asString()`**

Replace the whole `asString()` method body in `DES.java` with:

```java
    @Override
    public @Nonnull String asString() {
        return composeName(true, true, false);
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#desComposesKeyLengthAndModeButNotPadding`
Expected: PASS.

- [ ] **Step 5: Format, style, commit**

```bash
mvn spotless:apply -q && mvn checkstyle:check -q -pl mapper
git add mapper/src/main/java/com/ibm/mapper/model/algorithms/DES.java \
        mapper/src/test/java/com/ibm/mapper/model/algorithms/AlgorithmNameCompositionTest.java
git commit -m "Fix DES composition to DES-{keyLength}-{mode} per schema"
```

---

### Task 4: Block-cipher renames + composition

Covers: `Aria`→`ARIA`, `Camellia`→`CAMELLIA`, `cast/CAST128`→`CAST5`, `cast/CAST256`→`CAST6`, `Twofish`, `Serpent`, `Blowfish`, `SEED`, `RC2`, `RC5`, `RC6`, `TripleDES` (`3DES`), `SM4`, `IDEA`. Each currently emits only its bare `NAME` (no `asString` override).

**Files:**
- Modify (NAME + add `asString`): `algorithms/Aria.java`, `Camellia.java`, `cast/CAST128.java`, `cast/CAST256.java`, `Twofish.java`, `Serpent.java`, `Blowfish.java`, `SEED.java`, `RC2.java`, `RC5.java`, `RC6.java`, `TripleDES.java`, `SM4.java`, `IDEA.java`
- Test: `AlgorithmNameCompositionTest.java`

**Interfaces:**
- Consumes: `Algorithm.composeName` (Task 1).
- Produces composed names: `ARIA-256-CBC`, `CAMELLIA-256-CBC`, `CAST5-128-CBC`, `CAST6-256-CBC`, `Twofish-256-CBC`, `Serpent-256-CBC`, `Blowfish-128-CBC`, `SEED-128-CBC`, `RC2-64-CBC`, `RC5-128-CBC`, `RC6-128-CBC`, `3DES-168-CBC`, `SM4-CBC`, `IDEA-CBC`.

- [ ] **Step 1: Add failing tests**

Append (add imports for each class + `com.ibm.mapper.model.mode.CBC`):

```java
    @Test
    void blockCipherRenamesAndComposition() {
        Mode cbc = new CBC(TEST);
        assertThat(new Aria(256, cbc, TEST).asString()).isEqualTo("ARIA-256-CBC");
        assertThat(new Camellia(256, cbc, TEST).asString()).isEqualTo("CAMELLIA-256-CBC");
        assertThat(new CAST128(128, cbc, TEST).asString()).isEqualTo("CAST5-128-CBC");
        assertThat(new CAST256(256, cbc, TEST).asString()).isEqualTo("CAST6-256-CBC");
        assertThat(new Twofish(256, cbc, TEST).asString()).isEqualTo("Twofish-256-CBC");
        assertThat(new Serpent(256, cbc, TEST).asString()).isEqualTo("Serpent-256-CBC");
        assertThat(new Blowfish(128, cbc, TEST).asString()).isEqualTo("Blowfish-128-CBC");
        assertThat(new SEED(cbc, TEST).asString()).isEqualTo("SEED-128-CBC");
        assertThat(new RC2(64, cbc, TEST).asString()).isEqualTo("RC2-64-CBC");
        assertThat(new RC5(128, cbc, TEST).asString()).isEqualTo("RC5-128-CBC");
        assertThat(new RC6(128, cbc, TEST).asString()).isEqualTo("RC6-128-CBC");
        assertThat(new SM4(cbc, TEST).asString()).isEqualTo("SM4-CBC");
    }
```

> `TripleDES` and `IDEA` constructor shapes differ (verify in-file). Add their assertions using whatever `(…, Mode, DetectionLocation)` constructor exists, expecting `3DES-168-CBC` and `IDEA-CBC` respectively; if `TripleDES` has no key-length child by default, expect `3DES-CBC`.

- [ ] **Step 2: Run to verify it fails**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#blockCipherRenamesAndComposition`
Expected: FAIL — actual values are bare tokens (`Aria`, `Camellia`, `CAST-128`, `Twofish`, …).

- [ ] **Step 3: Rename NAME constants**

Edit each file's `NAME`:
- `Aria.java`: `"Aria"` → `"ARIA"`
- `Camellia.java`: `"Camellia"` → `"CAMELLIA"`
- `cast/CAST128.java`: `"CAST-128"` → `"CAST5"`
- `cast/CAST256.java`: `"CAST-256"` → `"CAST6"`

(`Twofish`, `Serpent`, `Blowfish`, `SEED`, `RC2`, `RC5`, `RC6`, `TripleDES`=`3DES`, `SM4`, `IDEA` keep their existing `NAME`.)

- [ ] **Step 4: Add `asString()` overrides**

Add this override to each class, choosing flags per the spec's Section 2.1 wiring:

- `(true,true,true)` — `Aria`, `Camellia`, `Twofish`, `Serpent`, `Blowfish`, `SEED`:
```java
    @Override
    public @Nonnull String asString() {
        return composeName(true, true, true);
    }
```
- `(true,true,false)` — `CAST128`, `CAST256`, `RC2`, `RC5`, `RC6`, `TripleDES`:
```java
    @Override
    public @Nonnull String asString() {
        return composeName(true, true, false);
    }
```
- `(false,true,false)` — `SM4`, `IDEA`:
```java
    @Override
    public @Nonnull String asString() {
        return composeName(false, true, false);
    }
```

Ensure `import javax.annotation.Nonnull;` exists in each file (most already have it).

- [ ] **Step 5: Run to verify it passes**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#blockCipherRenamesAndComposition`
Expected: PASS.

- [ ] **Step 6: Format, style, commit**

```bash
mvn spotless:apply -q && mvn checkstyle:check -q -pl mapper
git add mapper/src/main/java/com/ibm/mapper/model/algorithms/ \
        mapper/src/test/java/com/ibm/mapper/model/algorithms/AlgorithmNameCompositionTest.java
git commit -m "Rename and compose block-cipher names per CycloneDX schema"
```

---

### Task 5: Key-length-only ciphers (RC4, ElGamal) + ChaCha20-Poly1305 join

**Files:**
- Modify: `algorithms/RC4.java`, `algorithms/ElGamal.java`, `algorithms/ChaCha20.java`
- Test: `AlgorithmNameCompositionTest.java`

**Interfaces:**
- Produces: `RC4-128`, `ElGamal-2048`, and `ChaCha20`+Poly1305 join → `ChaCha20-Poly1305`.

- [ ] **Step 1: Add failing tests**

Append (add imports `RC4`, `ElGamal`, `ChaCha20`, `com.ibm.mapper.model.algorithms.Poly1305`):

```java
    @Test
    void keyLengthOnlyCiphers() {
        assertThat(new RC4(128, TEST).asString()).isEqualTo("RC4-128");
        assertThat(new ElGamal(2048, TEST).asString()).isEqualTo("ElGamal-2048");
    }

    @Test
    void chaCha20JoinsPoly1305WithHyphen() {
        ChaCha20 c = new ChaCha20(TEST);
        c.put(new Poly1305(TEST));
        assertThat(c.asString()).isEqualTo("ChaCha20-Poly1305");
    }
```

> Verify `ChaCha20` stores `Poly1305` under the `Mac` type (its current `asString` filters `hasChildOfType(Mac.class)`); if the constructor used differs, mirror how `ChaCha20Poly1305.java` wires it.

- [ ] **Step 2: Run to verify it fails**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#keyLengthOnlyCiphers+chaCha20JoinsPoly1305WithHyphen`
Expected: FAIL — `RC4`/`ElGamal` bare; ChaCha20 join yields `ChaCha20Poly1305` (no hyphen).

- [ ] **Step 3: Add `asString()` to RC4 and ElGamal**

Both use `(true,false,false)`:

```java
    @Override
    public @Nonnull String asString() {
        return composeName(true, false, false);
    }
```

- [ ] **Step 4: Fix the ChaCha20 Poly1305 join separator**

In `ChaCha20.java`, change the map line from:

```java
                .map(node -> this.name + ((IAlgorithm) node).getName())
```
to:
```java
                .map(node -> this.name + "-" + ((IAlgorithm) node).getName())
```

- [ ] **Step 5: Run to verify it passes**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#keyLengthOnlyCiphers+chaCha20JoinsPoly1305WithHyphen`
Expected: PASS.

- [ ] **Step 6: Format, style, commit**

```bash
mvn spotless:apply -q && mvn checkstyle:check -q -pl mapper
git add mapper/src/main/java/com/ibm/mapper/model/algorithms/RC4.java \
        mapper/src/main/java/com/ibm/mapper/model/algorithms/ElGamal.java \
        mapper/src/main/java/com/ibm/mapper/model/algorithms/ChaCha20.java \
        mapper/src/test/java/com/ibm/mapper/model/algorithms/AlgorithmNameCompositionTest.java
git commit -m "Compose RC4/ElGamal key length and hyphenate ChaCha20-Poly1305"
```

---

### Task 6: Ascon standardized-subset renames

**Files:**
- Modify (NAME only): `algorithms/ascon/Ascon128.java`, `ascon/AsconHash.java`, `ascon/AsconXof.java`
- Test: `AlgorithmNameCompositionTest.java`

**Interfaces:**
- Produces: `Ascon-AEAD128`, `Ascon-Hash256`, `Ascon-XOF128` (fixed tokens, no composition).

- [ ] **Step 1: Add failing tests**

Append (add imports for the three classes):

```java
    @Test
    void asconStandardizedNames() {
        assertThat(new Ascon128(TEST).asString()).isEqualTo("Ascon-AEAD128");
        assertThat(new AsconHash(TEST).asString()).isEqualTo("Ascon-Hash256");
        assertThat(new AsconXof(TEST).asString()).isEqualTo("Ascon-XOF128");
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#asconStandardizedNames`
Expected: FAIL — actual `Ascon-128`, `Ascon-Hash`, `Ascon-Xof`.

- [ ] **Step 3: Rename NAME constants**

- `Ascon128.java`: `"Ascon-128"` → `"Ascon-AEAD128"`
- `AsconHash.java`: `"Ascon-Hash"` → `"Ascon-Hash256"`
- `AsconXof.java`: `"Ascon-Xof"` → `"Ascon-XOF128"`

- [ ] **Step 4: Run to verify it passes**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#asconStandardizedNames`
Expected: PASS.

- [ ] **Step 5: Format, style, commit**

```bash
mvn spotless:apply -q && mvn checkstyle:check -q -pl mapper
git add mapper/src/main/java/com/ibm/mapper/model/algorithms/ascon/ \
        mapper/src/test/java/com/ibm/mapper/model/algorithms/AlgorithmNameCompositionTest.java
git commit -m "Rename Ascon standardized subset to Ascon-AEAD128/-Hash256/-XOF128"
```

---

### Task 7: KDF renames

**Files:**
- Modify (NAME only): `algorithms/Scrypt.java`, `algorithms/KDFDoublePipeline.java`, `algorithms/ANSIX942.java`, `algorithms/ANSIX963.java`
- Test: `AlgorithmNameCompositionTest.java`

**Interfaces:**
- Produces: `scrypt`, `SP800_108_DoublePipelineKDF`, `ANSI-KDF-X9.42`, `ANSI-KDF-X9.63`.

- [ ] **Step 1: Add failing tests**

Append (add imports for the four classes):

```java
    @Test
    void kdfSchemaNames() {
        assertThat(new Scrypt(TEST).asString()).isEqualTo("scrypt");
        assertThat(new KDFDoublePipeline(TEST).asString()).isEqualTo("SP800_108_DoublePipelineKDF");
        assertThat(new ANSIX942(TEST).asString()).isEqualTo("ANSI-KDF-X9.42");
        assertThat(new ANSIX963(TEST).asString()).isEqualTo("ANSI-KDF-X9.63");
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#kdfSchemaNames`
Expected: FAIL — actual `SCRYPT`, `KDF in Double-Pipeline Mode`, `ANSI X9.42`, `ANSI X9.63`.

- [ ] **Step 3: Rename NAME constants**

- `Scrypt.java`: `"SCRYPT"` → `"scrypt"`
- `KDFDoublePipeline.java`: `"KDF in Double-Pipeline Mode"` → `"SP800_108_DoublePipelineKDF"`
- `ANSIX942.java`: `"ANSI X9.42"` → `"ANSI-KDF-X9.42"`
- `ANSIX963.java`: `"ANSI X9.63"` → `"ANSI-KDF-X9.63"`

- [ ] **Step 4: Run to verify it passes**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#kdfSchemaNames`
Expected: PASS.

- [ ] **Step 5: Format, style, commit**

```bash
mvn spotless:apply -q && mvn checkstyle:check -q -pl mapper
git add mapper/src/main/java/com/ibm/mapper/model/algorithms/Scrypt.java \
        mapper/src/main/java/com/ibm/mapper/model/algorithms/KDFDoublePipeline.java \
        mapper/src/main/java/com/ibm/mapper/model/algorithms/ANSIX942.java \
        mapper/src/main/java/com/ibm/mapper/model/algorithms/ANSIX963.java \
        mapper/src/test/java/com/ibm/mapper/model/algorithms/AlgorithmNameCompositionTest.java
git commit -m "Rename KDF algorithms to CycloneDX schema names"
```

---

### Task 8: PQC rename (XMSSMT) + verify PQC composed names

**Files:**
- Modify (NAME only): `algorithms/XMSSMT.java`
- Test: `AlgorithmNameCompositionTest.java`

**Interfaces:**
- Produces: `XMSSMT`. Verifies `ML-DSA-65`, `ML-KEM-768`, and `SLH-DSA` composed forms already match.

- [ ] **Step 1: Add tests (one failing, others as verification)**

Append (add imports `XMSSMT`, `MLDSA`, `MLKEM`, `com.ibm.mapper.model.ParameterSetIdentifier`):

```java
    @Test
    void xmssmtDropsCaretSeparator() {
        assertThat(new XMSSMT(TEST).asString()).isEqualTo("XMSSMT");
    }

    @Test
    void mlDsaAndMlKemParameterSets() {
        MLDSA d = new MLDSA(TEST);
        d.put(new ParameterSetIdentifier("65", TEST));
        assertThat(d.asString()).isEqualTo("ML-DSA-65");
        MLKEM k = new MLKEM(TEST);
        k.put(new ParameterSetIdentifier("768", TEST));
        assertThat(k.asString()).isEqualTo("ML-KEM-768");
    }
```

> Verify the `ParameterSetIdentifier(String, DetectionLocation)` constructor signature in-file; if it takes an `int`, pass `65`/`768` as ints. If `MLDSA`/`MLKEM` default constructors already attach a parameter set, adjust the expected string to the real composed value (these two assertions are verification, not renames — do not change model code for them).

- [ ] **Step 2: Run to verify `xmssmt` fails, others reveal actual**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#xmssmtDropsCaretSeparator+mlDsaAndMlKemParameterSets`
Expected: `xmssmt…` FAILS (actual `XMSS^MT`). If `mlDsa…` fails, read the actual value and correct the test expectation (verification only).

- [ ] **Step 3: Rename XMSSMT**

`XMSSMT.java`: `"XMSS^MT"` → `"XMSSMT"`.

- [ ] **Step 4: Run to verify it passes**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#xmssmtDropsCaretSeparator+mlDsaAndMlKemParameterSets`
Expected: PASS.

- [ ] **Step 5: Format, style, commit**

```bash
mvn spotless:apply -q && mvn checkstyle:check -q -pl mapper
git add mapper/src/main/java/com/ibm/mapper/model/algorithms/XMSSMT.java \
        mapper/src/test/java/com/ibm/mapper/model/algorithms/AlgorithmNameCompositionTest.java
git commit -m "Rename XMSSMT to schema token and pin ML-DSA/ML-KEM composed names"
```

---

### Task 9: BLAKE composed-name verification

**Files:**
- Modify (only if verification fails): `algorithms/blake/BLAKE2b.java`, `BLAKE2s.java`, `BLAKE3.java`
- Test: `AlgorithmNameCompositionTest.java`

**Interfaces:**
- Produces/verifies: `BLAKE2b-256`, `BLAKE2s-256`.

- [ ] **Step 1: Add verification tests**

Append (add imports `BLAKE2b`, `BLAKE2s`, `com.ibm.mapper.model.DigestSize`):

```java
    @Test
    void blake2ComposesDigestSize() {
        assertThat(new BLAKE2b(256, false, TEST).asString()).isEqualTo("BLAKE2b-256");
        assertThat(new BLAKE2s(256, false, TEST).asString()).isEqualTo("BLAKE2s-256");
    }
```

> Confirm the `(int digestSize, boolean isParallel, DetectionLocation)` constructors exist (they do for BLAKE2b; verify BLAKE2s). BLAKE2b/2s currently have **no** `asString` override, so a bare `BLAKE2b` will be produced.

- [ ] **Step 2: Run to reveal behavior**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#blake2ComposesDigestSize`
Expected: FAIL — actual `BLAKE2b` (digest size not composed).

- [ ] **Step 3: Add digest-size composition to BLAKE2b and BLAKE2s**

Add to each class (pattern `BLAKE2b-(160|256|384|512)`):

```java
    @Override
    public @Nonnull String asString() {
        final StringBuilder sb = new StringBuilder(this.name);
        this.hasChildOfType(DigestSize.class).ifPresent(d -> sb.append("-").append(d.asString()));
        return sb.toString();
    }
```

Add `import com.ibm.mapper.model.DigestSize;` and `import javax.annotation.Nonnull;` if missing.

- [ ] **Step 4: Run to verify it passes**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#blake2ComposesDigestSize`
Expected: PASS.

- [ ] **Step 5: Format, style, commit**

```bash
mvn spotless:apply -q && mvn checkstyle:check -q -pl mapper
git add mapper/src/main/java/com/ibm/mapper/model/algorithms/blake/ \
        mapper/src/test/java/com/ibm/mapper/model/algorithms/AlgorithmNameCompositionTest.java
git commit -m "Compose BLAKE2b/BLAKE2s digest size per schema"
```

---

### Task 10: CMAC component-order rework

**Files:**
- Modify: `algorithms/CMAC.java`
- Test: `AlgorithmNameCompositionTest.java`

**Interfaces:**
- Produces: `CMAC-AES` (schema `CMAC[-{cipherAlgorithm}]`), replacing current `AES-CMAC`.

- [ ] **Step 1: Add the failing test**

Append (add import `CMAC`; AES already imported):

```java
    @Test
    void cmacPutsCipherAfterName() {
        CMAC cmac = new CMAC(new AES(TEST));
        assertThat(cmac.asString()).isEqualTo("CMAC-AES");
    }
```

> Verify the `CMAC(BlockCipher, ...)` / `CMAC(AES, ...)` constructor shape in-file and adjust construction to match; the assertion target `CMAC-AES` is fixed.

- [ ] **Step 2: Run to verify it fails**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#cmacPutsCipherAfterName`
Expected: FAIL — actual `AES-CMAC`.

- [ ] **Step 3: Rework `CMAC.asString()`**

Replace:

```java
        return this.hasChildOfType(BlockCipher.class)
                .map(node -> ((IAlgorithm) node).getName() + "-" + this.name)
                .orElse(this.name);
```
with:
```java
        return this.hasChildOfType(BlockCipher.class)
                .map(node -> this.name + "-" + ((IAlgorithm) node).getName())
                .orElse(this.name);
```

- [ ] **Step 4: Run to verify it passes**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#cmacPutsCipherAfterName`
Expected: PASS.

- [ ] **Step 5: Format, style, commit**

```bash
mvn spotless:apply -q && mvn checkstyle:check -q -pl mapper
git add mapper/src/main/java/com/ibm/mapper/model/algorithms/CMAC.java \
        mapper/src/test/java/com/ibm/mapper/model/algorithms/AlgorithmNameCompositionTest.java
git commit -m "Reorder CMAC name to CMAC-{cipher} per schema"
```

---

### Task 11: Asymmetric order rework (DSA, RSA, RSAssaPSS) + MQV→FFMQV

**Files:**
- Modify: `algorithms/DSA.java`, `algorithms/RSA.java`, `algorithms/RSAssaPSS.java`, `algorithms/MQV.java`
- Test: `AlgorithmNameCompositionTest.java`

**Interfaces:**
- Produces: `DSA-2048-SHA-256` (schema `DSA[-{length}][-{hashAlgorithm}]`); `RSA-PKCS1-1.5-SHA-256` for a plain RSA signature with a digest; `FFMQV`.

- [ ] **Step 1: Add failing tests**

Append (add imports `DSA`, `MQV`, `com.ibm.mapper.model.algorithms.SHA2`, `com.ibm.mapper.model.KeyLength`):

```java
    @Test
    void dsaPutsLengthThenHash() {
        DSA dsa = new DSA(TEST);
        dsa.put(new KeyLength(2048, TEST));
        dsa.put(new SHA2(256, TEST));
        assertThat(dsa.asString()).isEqualTo("DSA-2048-SHA-256");
    }

    @Test
    void mqvUsesFiniteFieldName() {
        assertThat(new MQV(TEST).asString()).isEqualTo("FFMQV");
    }
```

> RSA is the highest-risk change. Before writing its assertions, read `RSA.java` fully and enumerate its variants (PKCS#1 v1.5 signature, OAEP encryption, key-length-only). Add one assertion per variant with the schema target: signature+digest → `RSA-PKCS1-1.5-SHA-256`; OAEP padding → `RSA-OAEP` (already correct); key-length-only encryption → `RSA-PKCS1-1.5-2048`. Match construction to the real constructors.

- [ ] **Step 2: Run to verify it fails**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest#dsaPutsLengthThenHash+mqvUsesFiniteFieldName`
Expected: FAIL — DSA actual `SHA-256-DSA`; MQV actual `MQV`.

- [ ] **Step 3: Rework DSA**

Replace `DSA.asString()` with length-then-hash ordering:

```java
    @Override
    public @Nonnull String asString() {
        final StringBuilder sb = new StringBuilder(this.name);
        this.hasChildOfType(KeyLength.class).ifPresent(k -> sb.append("-").append(k.asString()));
        this.hasChildOfType(MessageDigest.class)
                .ifPresent(d -> sb.append("-").append(d.asString()));
        return sb.toString();
    }
```

Add `import com.ibm.mapper.model.KeyLength;` / `MessageDigest` if missing.

- [ ] **Step 4: Rename MQV**

`MQV.java`: `"MQV"` → `"FFMQV"`.

- [ ] **Step 5: Rework RSA per its variants**

In `RSA.java`, change the signature branch so the family token precedes the digest, matching schema `RSA-PKCS1-1.5[-{digestAlgorithm}][-{keyLength}]`. Replace the signature branch:

```java
        if (this.is(Signature.class)) {
            return this.hasChildOfType(MessageDigest.class)
                    .map(node -> node.asString() + "-" + this.name)
                    .orElse(this.name);
        }
```
with:
```java
        if (this.is(Signature.class)) {
            final StringBuilder sb = new StringBuilder(this.name).append("-PKCS1-1.5");
            this.hasChildOfType(MessageDigest.class)
                    .ifPresent(node -> sb.append("-").append(node.asString()));
            return sb.toString();
        }
```

Leave the existing OAEP branch (`return this.name + "-OAEP";`) and key-length branch as-is unless the RSA verification assertions from Step 1 show a mismatch; if the key-length encryption branch must read `RSA-PKCS1-1.5-2048`, prefix it with `-PKCS1-1.5` the same way. Update `RSAssaPSS.java` only if its composed output (from a Step-1 assertion) does not already yield `RSA-PSS…`.

- [ ] **Step 6: Run to verify it passes**

Run: `mvn test -pl mapper -Dtest=AlgorithmNameCompositionTest`
Expected: PASS (all composition tests, whole class).

- [ ] **Step 7: Format, style, commit**

```bash
mvn spotless:apply -q && mvn checkstyle:check -q -pl mapper
git add mapper/src/main/java/com/ibm/mapper/model/algorithms/DSA.java \
        mapper/src/main/java/com/ibm/mapper/model/algorithms/RSA.java \
        mapper/src/main/java/com/ibm/mapper/model/algorithms/RSAssaPSS.java \
        mapper/src/main/java/com/ibm/mapper/model/algorithms/MQV.java \
        mapper/src/test/java/com/ibm/mapper/model/algorithms/AlgorithmNameCompositionTest.java
git commit -m "Rework RSA/DSA name ordering and rename MQV to FFMQV per schema"
```

---

### Task 12: Stabilize mapper + java module fixtures

The model is now schema-correct and the composition unit test is green; downstream assertions across the mapper (non-composition) and java modules are stale. This task makes them green by mechanical old→new substitution.

**Files:**
- Modify: failing test files under `mapper/src/test/**` and `java/src/test/**` (and `java/src/test/files/**` fixtures)

**Interfaces:**
- Consumes: all model changes (Tasks 1–11).

- [ ] **Step 1: Run the mapper + java suites and capture failures**

Run: `mvn test -pl mapper,java 2>&1 | tee /tmp/mig-java.log`
Expected: multiple assertion failures of the form `expected "AES-256-CBC" but was "AES256-CBC"` inverted (expected = old string, actual = new schema string).

- [ ] **Step 2: Update each failing assertion to the new composed name**

For every failure, open the named test file and replace the **expected** literal with the **actual** value the test now produces — but only when that new value corresponds to a Section 6 rename/composition rule (spec). Concrete example:

```java
// before
assertThat(value.asString()).isEqualTo("Aria");
// after
assertThat(value.asString()).isEqualTo("ARIA-256-CBC");
```

Do **not** change a test whose failure is unrelated to a naming rule — investigate those instead. Do **not** delete or `@Disabled` any test. Re-run the targeted class after each file (`mvn test -pl java -Dtest=<ClassName>`) to confirm.

- [ ] **Step 3: Run the full mapper + java suites green**

Run: `mvn test -pl mapper,java`
Expected: BUILD SUCCESS.

- [ ] **Step 4: Format, style, commit**

```bash
mvn spotless:apply -q && mvn checkstyle:check -q -pl mapper,java
git add mapper/src/test java/src/test
git commit -m "Update mapper and java test assertions to schema algorithm names"
```

---

### Task 13: Stabilize python module fixtures

**Files:**
- Modify: failing test files under `python/src/test/**`

- [ ] **Step 1: Run the python suite and capture failures**

Run: `mvn test -pl python 2>&1 | tee /tmp/mig-python.log`
Expected: assertion failures naming renamed algorithms (e.g. `SHA-3` vs `SHA3`, `ChaCha20-Poly1305`).

- [ ] **Step 2: Update each failing assertion to the new name**

Same rule as Task 12 Step 2 — replace stale expected literals with the new schema value where it corresponds to a Section 6 rule; investigate anything else; never weaken/delete tests. Re-run per class: `mvn test -pl python -Dtest=<ClassName>`.

- [ ] **Step 3: Run the python suite green**

Run: `mvn test -pl python`
Expected: BUILD SUCCESS.

- [ ] **Step 4: Format, style, commit**

```bash
mvn spotless:apply -q && mvn checkstyle:check -q -pl python
git add python/src/test
git commit -m "Update python test assertions to schema algorithm names"
```

---

### Task 14: Stabilize go module fixtures

**Files:**
- Modify: failing test files under `go/src/test/**` (module directory may be named differently — locate with `git ls-files | grep -i gocrypto | head`)

- [ ] **Step 1: Locate the go module and run its suite**

Run:
```bash
GO_MODULE=$(ls -d */ | grep -iE '^go' | head -1); echo "module: $GO_MODULE"
mvn test -pl "${GO_MODULE%/}" 2>&1 | tee /tmp/mig-go.log
```
Expected: assertion failures naming renamed algorithms (the prior commit already touched `GoCryptoSHA3` etc.; remaining failures are the newly renamed names).

- [ ] **Step 2: Update each failing assertion to the new name**

Same rule as Task 12 Step 2. Re-run per class.

- [ ] **Step 3: Run the go suite green**

Run: `mvn test -pl "${GO_MODULE%/}"`
Expected: BUILD SUCCESS.

- [ ] **Step 4: Format, style, commit**

```bash
mvn spotless:apply -q && mvn checkstyle:check -q
git add "${GO_MODULE%/}/src/test"
git commit -m "Update go test assertions to schema algorithm names"
```

---

### Task 15: Regenerate CBOM fixture + full-suite green

**Files:**
- Modify: `sonar-cryptography-plugin/bom/bom.json` (regenerated)
- Verify: whole repository

**Interfaces:**
- Consumes: all prior tasks.

- [ ] **Step 1: Run the full suite to find remaining fixture drift**

Run: `mvn test 2>&1 | tee /tmp/mig-full.log`
Expected: only `bom.json`-related and any straggler cross-module assertions remain (a name used by a fixture in a module not yet touched).

- [ ] **Step 2: Regenerate `bom.json`**

Determine how the fixture is produced. If a test writes it (search `git log -p -- sonar-cryptography-plugin/bom/bom.json | head`), run that path; otherwise regenerate via the plugin build that emits the CBOM:
```bash
mvn clean package -pl sonar-cryptography-plugin -am -DskipTests
```
Then diff the regenerated `bom.json` against the committed one and confirm **every** change is a name rename from Section 6 (no structural changes, no lost components):
```bash
git diff --stat sonar-cryptography-plugin/bom/bom.json
git diff sonar-cryptography-plugin/bom/bom.json | grep -E '^[-+].*"name"' | sort | uniq -c | head -50
```

- [ ] **Step 3: Fix any straggler assertions**

For any remaining failures, apply the Task 12 Step 2 rule.

- [ ] **Step 4: Run the entire suite green + style gates**

Run:
```bash
mvn spotless:apply -q && mvn checkstyle:check -q && mvn test
```
Expected: BUILD SUCCESS across all modules.

- [ ] **Step 5: Commit**

```bash
git add sonar-cryptography-plugin/bom/bom.json
git add -A
git commit -m "Regenerate CBOM fixture for schema algorithm names; full suite green"
```

---

## Self-Review Notes

- **Spec coverage:** Every Section 6 row maps to a task — renames R (Tasks 2,4,6,7,8,11), separator/composition S (Tasks 1,3,4,5,9), order O (Tasks 5,10,11); "verify" rows are Tasks 8/9; downstream + fixture in Tasks 12–15. Out-of-scope classes are never touched (Global Constraints).
- **Risk containment:** RSA/DSA/CMAC (order reworks) each get their own dedicated unit assertions before any downstream fixture moves, per spec Section 9.
- **Verification-driven tasks (12–15):** the "update the assertion" steps are mechanical old→new string substitutions driven by deterministic, reproducible test output, with an explicit rule (must correspond to a Section 6 change; never weaken/delete) and a worked example — not open-ended placeholders.
