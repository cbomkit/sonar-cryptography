# Crypto Behavior Context Layer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a scan-wide contextual-evidence layer that detects application-level auth interfaces (JWT, servlet principal) and combines them with crypto-derived behaviors via a two-tier inference engine, so app-level taxonomy behaviors (`authenticates`, `validatesToken`, `usesIdentity`) are gated behind a real interface.

**Architecture:** Contextual signals bypass the crypto `INode` stream: new AST detection rules tagged with a new `AuthContext` are routed, in `JavaBaseDetectionRule.update()`, into a scan-wide `BehaviorEvidenceStore` (never becoming crypto components). At emission, `CBOMOutputFile` runs a `BehaviorInferenceEngine` over the union of crypto behaviors + the auth signals, producing a `Set<CryptoBehavior>` that is written as one comma-joined property on `metadata.component`.

**Tech Stack:** Java 17, Maven multi-module, SonarQube plugin (sonar-java `IssuableSubscriptionVisitor`), JUnit 5 + AssertJ, sonar-java `CheckVerifier`, CycloneDX model.

## Global Constraints

- Java 17; follow existing module boundaries: `engine` (no deps) → `mapper`/`output` (depend on `engine`) → `java` (depends on `engine`, `mapper`, `output`) → `sonar-cryptography-plugin` (depends on `java`, `output`).
- Apache 2.0 license header required in every new `.java` file (Spotless applies it on `mvn package`; copy the header verbatim from any existing file in the same module).
- Code style: Google Java Format (AOSP) via Spotless; Checkstyle: no unused imports, `@Override` required, private utility constructors. Run `mvn spotless:apply` before committing.
- Property namespace is experimental: name stays `cbomkit:crypto:behavior`.
- Phase 1 detection scope: **JWT** (`io.jsonwebtoken`) and **PRINCIPAL** (`jakarta.servlet.http.HttpServletRequest`) only. `OAUTH` and `SAML` are defined in the `AuthContext.Kind` enum and handled by the inference engine, but their detection rules are deferred (documented, not built).
- Inference is total: never throws; unknown/insufficient evidence → behavior simply absent.

---

## File Structure

- `engine/.../model/context/AuthContext.java` — CREATE — new detection-context kind.
- `output/.../behavior/CryptoBehavior.java` — MODIFY — add `VALIDATES_TOKEN`, `USES_IDENTITY`.
- `output/.../behavior/BehaviorInferenceEngine.java` — CREATE — two-tier decision logic.
- `output/.../IOutputFileFactory.java` — MODIFY — factory signature gains `authSignals`.
- `output/.../cyclondx/CBOMOutputFileFactory.java` — MODIFY — pass `authSignals` through.
- `output/.../cyclondx/CBOMOutputFile.java` — MODIFY — ctor arg + inference at emission + value format.
- `java/.../rules/detection/auth/AuthInterfaceDetection.java` — CREATE — Phase-1 auth rules.
- `java/.../rules/detection/auth/AuthDetectionRules.java` — CREATE — aggregator.
- `java/.../rules/detection/JavaDetectionRules.java` — MODIFY — wire in auth rules.
- `java/.../plugin/BehaviorEvidenceStore.java` — CREATE — scan-wide auth-signal store.
- `java/.../rules/detection/JavaBaseDetectionRule.java` — MODIFY — route auth findings to store.
- `java/pom.xml` — MODIFY — add `jjwt-api` + `jakarta.servlet-api` test deps.
- `sonar-cryptography-plugin/.../ScannerManager.java` — MODIFY — pass store signals + reset.

Package note: `BehaviorEvidenceStore` is in package `com.ibm.plugin` (java module); `ScannerManager` is in package `com.ibm.plugin` (plugin module). This split package already exists — `ScannerManager` references `JavaAggregator` (also `com.ibm.plugin`, java module) with no import — so `BehaviorEvidenceStore` is likewise referenced without an import.

---

## Task 1: `AuthContext` detection-context kind (engine)

**Files:**
- Create: `engine/src/main/java/com/ibm/engine/model/context/AuthContext.java`
- Test: `engine/src/test/java/com/ibm/engine/model/context/AuthContextTest.java`

**Interfaces:**
- Consumes: `IDetectionContext`, `ISupportKind<K>` (existing, same package).
- Produces: `class AuthContext implements IDetectionContext, ISupportKind<AuthContext.Kind>`; `enum Kind { JWT, OAUTH, SAML, PRINCIPAL, NONE }`; `AuthContext(Kind)`, no-arg `AuthContext()` → `NONE`; `Kind kind()`; `Class<? extends IDetectionContext> type()` → `AuthContext.class`.

- [ ] **Step 1: Write the failing test**

```java
/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.engine.model.context;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AuthContextTest {

    @Test
    void carriesKindAndType() {
        final AuthContext context = new AuthContext(AuthContext.Kind.JWT);
        assertThat(context.kind()).isEqualTo(AuthContext.Kind.JWT);
        assertThat(context.type()).isEqualTo(AuthContext.class);
        assertThat(context.is(AuthContext.class)).isTrue();
    }

    @Test
    void defaultsToNone() {
        assertThat(new AuthContext().kind()).isEqualTo(AuthContext.Kind.NONE);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl engine -Dtest=AuthContextTest`
Expected: FAIL — compilation error, `AuthContext` does not exist.

- [ ] **Step 3: Write minimal implementation**

Create `engine/src/main/java/com/ibm/engine/model/context/AuthContext.java` (copy the license header verbatim from `ProtocolContext.java` in the same package):

```java
package com.ibm.engine.model.context;

import javax.annotation.Nonnull;

public class AuthContext implements IDetectionContext, ISupportKind<AuthContext.Kind> {

    public enum Kind {
        JWT,
        OAUTH,
        SAML,
        PRINCIPAL,
        NONE,
    }

    @Nonnull private final AuthContext.Kind kind;

    public AuthContext(@Nonnull AuthContext.Kind kind) {
        this.kind = kind;
    }

    public AuthContext() {
        this.kind = AuthContext.Kind.NONE;
    }

    @Nonnull
    @Override
    public Class<? extends IDetectionContext> type() {
        return AuthContext.class;
    }

    @Nonnull
    @Override
    public Kind kind() {
        return this.kind;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn test -pl engine -Dtest=AuthContextTest`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
mvn spotless:apply -pl engine
git add engine/src/main/java/com/ibm/engine/model/context/AuthContext.java engine/src/test/java/com/ibm/engine/model/context/AuthContextTest.java
git commit -m "feat(engine): add AuthContext detection-context kind for auth-interface signals"
```

---

## Task 2: Output enums — `CryptoBehavior` additions (output)

**Files:**
- Modify: `output/src/main/java/com/ibm/output/cyclondx/behavior/CryptoBehavior.java` (add two values after `AUTHENTICATES`, line ~40)
- Test: `output/src/test/java/com/ibm/output/cyclonedx/behavior/CryptoBehaviorAppLevelTest.java`
- Existing test that must stay green: `output/src/test/java/com/ibm/output/cyclonedx/behavior/CryptoBehaviorTaxonomyTest.java` (iterates every `CryptoBehavior.values()` and asserts it exists in `crypto-behavior-taxonomy.json`; `validatesToken` and `usesIdentity` are already in the snapshot).

**Interfaces:**
- Produces: `CryptoBehavior.VALIDATES_TOKEN` (`"validatesToken"`), `CryptoBehavior.USES_IDENTITY` (`"usesIdentity"`).

- [ ] **Step 1: Write the failing test**

Create `output/src/test/java/com/ibm/output/cyclonedx/behavior/CryptoBehaviorAppLevelTest.java` (copy header from `CryptoBehaviorTaxonomyTest.java`; note test package is `com.ibm.output.cyclonedx.behavior` — with an `e` — while the production package is `com.ibm.output.cyclondx.behavior` — no `e`; this mismatch is pre-existing, keep it):

```java
package com.ibm.output.cyclonedx.behavior;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.output.cyclondx.behavior.CryptoBehavior;
import org.junit.jupiter.api.Test;

class CryptoBehaviorAppLevelTest {

    @Test
    void newAppLevelBehaviorsExposeFullId() {
        assertThat(CryptoBehavior.VALIDATES_TOKEN.fullId())
                .isEqualTo("security:cryptography:validatesToken");
        assertThat(CryptoBehavior.USES_IDENTITY.fullId())
                .isEqualTo("security:cryptography:usesIdentity");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl output -Dtest=CryptoBehaviorAppLevelTest`
Expected: FAIL — the two new enum constants do not exist.

- [ ] **Step 3: Write minimal implementation**

In `CryptoBehavior.java`, insert the two new constants immediately after the `AUTHENTICATES("authenticates"),` line:

```java
    AUTHENTICATES("authenticates"),
    VALIDATES_TOKEN("validatesToken"),
    USES_IDENTITY("usesIdentity"),
    ENSURES_CONFIDENTIALITY("ensuresConfidentiality"),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mvn test -pl output -Dtest=CryptoBehaviorAppLevelTest,CryptoBehaviorTaxonomyTest`
Expected: PASS (CryptoBehaviorAppLevelTest 1 test; CryptoBehaviorTaxonomyTest still green — new enum values are present in the snapshot).

- [ ] **Step 5: Commit**

```bash
mvn spotless:apply -pl output
git add output/src/main/java/com/ibm/output/cyclondx/behavior/CryptoBehavior.java output/src/test/java/com/ibm/output/cyclonedx/behavior/CryptoBehaviorAppLevelTest.java
git commit -m "feat(output): add validatesToken/usesIdentity behaviors"
```

---

## Task 3: `BehaviorInferenceEngine` — two-tier decision logic (output)

**Files:**
- Create: `output/src/main/java/com/ibm/output/cyclondx/behavior/BehaviorInferenceEngine.java`
- Test: `output/src/test/java/com/ibm/output/cyclonedx/behavior/BehaviorInferenceEngineTest.java`

**Interfaces:**
- Consumes: `CryptoBehavior` (Task 2), `com.ibm.engine.model.context.AuthContext.Kind` (Task 1).
- Produces: `Set<CryptoBehavior> infer(Set<CryptoBehavior> cryptoBehaviors, Set<AuthContext.Kind> authSignals)`.

**Behavior contract (design §5):**
- Every crypto behavior passes through, **except** `AUTHENTICATES`, which is dropped from the crypto set (a MAC maps to `AUTHENTICATES` in the base mapper but only *corroborates*).
- `AUTHENTICATES` is (re)emitted iff any auth primary is present (`JWT`/`OAUTH`/`SAML`/`PRINCIPAL`).
- `VALIDATES_TOKEN` iff a token primary is present (`JWT`/`OAUTH`).
- `USES_IDENTITY` iff `PRINCIPAL` is present.
- `NONE` is never a primary.

- [ ] **Step 1: Write the failing test**

Create `output/src/test/java/com/ibm/output/cyclonedx/behavior/BehaviorInferenceEngineTest.java` (header + test package `com.ibm.output.cyclonedx.behavior`):

```java
package com.ibm.output.cyclonedx.behavior;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.output.cyclondx.behavior.BehaviorInferenceEngine;
import com.ibm.output.cyclondx.behavior.CryptoBehavior;
import java.util.EnumSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class BehaviorInferenceEngineTest {

    private final BehaviorInferenceEngine engine = new BehaviorInferenceEngine();

    @Test
    void macAloneDoesNotAuthenticate() {
        final Set<CryptoBehavior> result =
                engine.infer(
                        EnumSet.of(CryptoBehavior.AUTHENTICATES, CryptoBehavior.ENSURES_INTEGRITY),
                        Set.of());
        assertThat(result).doesNotContain(CryptoBehavior.AUTHENTICATES);
        assertThat(result).contains(CryptoBehavior.ENSURES_INTEGRITY);
    }

    @Test
    void macPlusJwtAuthenticatesAndValidatesToken() {
        final Set<CryptoBehavior> result =
                engine.infer(
                        EnumSet.of(CryptoBehavior.AUTHENTICATES, CryptoBehavior.ENSURES_INTEGRITY),
                        Set.of(AuthContext.Kind.JWT));
        assertThat(result).contains(CryptoBehavior.AUTHENTICATES);
        assertThat(result).contains(CryptoBehavior.VALIDATES_TOKEN);
        assertThat(result).contains(CryptoBehavior.ENSURES_INTEGRITY);
    }

    @Test
    void jwtWithoutCryptoStillYieldsTokenBehaviors() {
        final Set<CryptoBehavior> result =
                engine.infer(EnumSet.noneOf(CryptoBehavior.class), Set.of(AuthContext.Kind.JWT));
        assertThat(result)
                .containsOnly(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN);
    }

    @Test
    void principalYieldsUsesIdentityAndCorroboratesAuthenticates() {
        final Set<CryptoBehavior> result =
                engine.infer(
                        EnumSet.noneOf(CryptoBehavior.class), Set.of(AuthContext.Kind.PRINCIPAL));
        assertThat(result).contains(CryptoBehavior.USES_IDENTITY);
        assertThat(result).contains(CryptoBehavior.AUTHENTICATES);
        assertThat(result).doesNotContain(CryptoBehavior.VALIDATES_TOKEN);
    }

    @Test
    void cryptoOnlyPassesThroughUnchanged() {
        final Set<CryptoBehavior> result =
                engine.infer(
                        EnumSet.of(
                                CryptoBehavior.ENCRYPTS_DATA,
                                CryptoBehavior.ENSURES_CONFIDENTIALITY),
                        Set.of());
        assertThat(result)
                .containsOnly(
                        CryptoBehavior.ENCRYPTS_DATA,
                        CryptoBehavior.ENSURES_CONFIDENTIALITY);
    }

    @Test
    void noneKindIsNotAPrimary() {
        final Set<CryptoBehavior> result =
                engine.infer(EnumSet.noneOf(CryptoBehavior.class), Set.of(AuthContext.Kind.NONE));
        assertThat(result).isEmpty();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl output -Dtest=BehaviorInferenceEngineTest`
Expected: FAIL — `BehaviorInferenceEngine` does not exist.

- [ ] **Step 3: Write minimal implementation**

Create `output/src/main/java/com/ibm/output/cyclondx/behavior/BehaviorInferenceEngine.java` (header; package `com.ibm.output.cyclondx.behavior`):

```java
package com.ibm.output.cyclondx.behavior;

import com.ibm.engine.model.context.AuthContext;
import java.util.EnumSet;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Two-tier behavior inference (design §5). Combines crypto-derived behaviors with scan-wide
 * contextual auth signals. Crypto operational/goal behaviors pass through unchanged. Application-level
 * behaviors ({@code authenticates}, {@code validatesToken}, {@code usesIdentity}) are gated behind a
 * required auth-interface primary: crypto alone can never assert them. Total and side-effect free;
 * never throws.
 */
public final class BehaviorInferenceEngine {

    @Nonnull
    public Set<CryptoBehavior> infer(
            @Nonnull Set<CryptoBehavior> cryptoBehaviors,
            @Nonnull Set<AuthContext.Kind> authSignals) {
        final Set<CryptoBehavior> result = EnumSet.noneOf(CryptoBehavior.class);

        // Crypto behaviors pass through, except AUTHENTICATES which is gated below:
        // a MAC alone (mapped to authenticates by CryptoBehaviorMapper) only corroborates.
        for (CryptoBehavior behavior : cryptoBehaviors) {
            if (behavior == CryptoBehavior.AUTHENTICATES) {
                continue;
            }
            result.add(behavior);
        }

        final boolean hasAuthPrimary =
                authSignals.contains(AuthContext.Kind.JWT)
                        || authSignals.contains(AuthContext.Kind.OAUTH)
                        || authSignals.contains(AuthContext.Kind.SAML)
                        || authSignals.contains(AuthContext.Kind.PRINCIPAL);
        final boolean hasTokenPrimary =
                authSignals.contains(AuthContext.Kind.JWT)
                        || authSignals.contains(AuthContext.Kind.OAUTH);
        final boolean hasPrincipal = authSignals.contains(AuthContext.Kind.PRINCIPAL);

        if (hasAuthPrimary) {
            result.add(CryptoBehavior.AUTHENTICATES);
        }
        if (hasTokenPrimary) {
            result.add(CryptoBehavior.VALIDATES_TOKEN);
        }
        if (hasPrincipal) {
            result.add(CryptoBehavior.USES_IDENTITY);
        }
        return result;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn test -pl output -Dtest=BehaviorInferenceEngineTest`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
mvn spotless:apply -pl output
git add output/src/main/java/com/ibm/output/cyclondx/behavior/BehaviorInferenceEngine.java output/src/test/java/com/ibm/output/cyclonedx/behavior/BehaviorInferenceEngineTest.java
git commit -m "feat(output): add two-tier BehaviorInferenceEngine gating app-level behaviors"
```

---

## Task 4: Wire inference into CBOM emission + value format (output)

**Files:**
- Modify: `output/src/main/java/com/ibm/output/IOutputFileFactory.java`
- Modify: `output/src/main/java/com/ibm/output/cyclondx/CBOMOutputFileFactory.java`
- Modify: `output/src/main/java/com/ibm/output/cyclondx/CBOMOutputFile.java` (fields ~108-118; behavior block ~353-367)
- Test: `output/src/test/java/com/ibm/output/cyclonedx/CryptoBehaviorMetadataTest.java` (update expectations)

**Interfaces:**
- Consumes: `BehaviorInferenceEngine` (Task 3), `AuthContext.Kind` (Task 1).
- Produces: `CBOMOutputFile(Set<AuthContext.Kind> authSignals)` constructor (plus a no-arg constructor delegating to an empty set); `IOutputFileFactory.createOutputFormat(List<INode> nodes, Set<AuthContext.Kind> authSignals)`.

- [ ] **Step 1: Update the failing test**

In `CryptoBehaviorMetadataTest.java`, replace the exact-value assertion in `aggregatesBehaviorsOfWholeScanOntoMetadataComponent()` (currently expecting the list including `authenticates`). The HMAC-only scenario has no auth primary, so `authenticates` is now **gated out**:

```java
        assertThat(property.getValue())
                .isEqualTo(
                        "security:cryptography:encryptsData,"
                                + "security:cryptography:ensuresConfidentiality,"
                                + "security:cryptography:ensuresIntegrity,"
                                + "security:cryptography:hashesData");
```

Add a new test in the same class proving the gate opens when an auth signal is present. Add imports `com.ibm.engine.model.context.AuthContext` and `java.util.Set` at the top:

```java
    @Test
    void authInterfaceUnlocksAuthenticatesAndValidatesToken() {
        final AES aes = new AES(loc);
        aes.put(new Encrypt(loc));
        final CBOMOutputFile outputFile = new CBOMOutputFile(Set.of(AuthContext.Kind.JWT));
        outputFile.add(List.of(aes));
        final Bom bom = outputFile.getBom();

        final Property property = bom.getMetadata().getComponent().getProperties().get(0);
        assertThat(property.getValue())
                .contains("security:cryptography:authenticates")
                .contains("security:cryptography:validatesToken")
                .contains("security:cryptography:encryptsData");
    }
```

(The `protocolCipherSuiteConstituentsContributeBehaviors` test uses `.contains("security:cryptography:decryptsData")` etc.; those substrings still match inside the comma-joined value, so that test needs no change. `noMetadataComponentWhenNoBehaviorsDetected` also stays valid — empty inference → no component.)

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl output -Dtest=CryptoBehaviorMetadataTest`
Expected: FAIL — the new `CBOMOutputFile(Set)` constructor does not exist (compile error) and/or the value format differs.

- [ ] **Step 3: Modify `IOutputFileFactory`**

Replace the method and add imports (`java.util.Set`, `com.ibm.engine.model.context.AuthContext`):

```java
package com.ibm.output;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.mapper.model.INode;
import com.ibm.output.cyclondx.CBOMOutputFileFactory;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;

public interface IOutputFileFactory {
    public static IOutputFileFactory DEFAULT = new CBOMOutputFileFactory();

    @Nonnull
    IOutputFile createOutputFormat(
            @Nonnull List<INode> nodes, @Nonnull Set<AuthContext.Kind> authSignals);
}
```

- [ ] **Step 4: Modify `CBOMOutputFileFactory`**

```java
package com.ibm.output.cyclondx;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.mapper.model.INode;
import com.ibm.output.IOutputFileFactory;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;

public class CBOMOutputFileFactory implements IOutputFileFactory {
    @Nonnull
    @Override
    public CBOMOutputFile createOutputFormat(
            @Nonnull List<INode> nodes, @Nonnull Set<AuthContext.Kind> authSignals) {
        CBOMOutputFile outputFile = new CBOMOutputFile(authSignals);
        outputFile.add(nodes);
        return outputFile;
    }
}
```

- [ ] **Step 5: Modify `CBOMOutputFile`**

Add imports near the top: `com.ibm.engine.model.context.AuthContext`, `com.ibm.output.cyclondx.behavior.BehaviorInferenceEngine`, `java.util.Set` (and confirm `java.util.Set` and `CryptoBehavior` are imported).

Add two fields alongside `aggregatedBehaviors`/`behaviorMapper` (~line 108-111):

```java
    @Nonnull private final Set<AuthContext.Kind> authSignals;

    @Nonnull
    private final BehaviorInferenceEngine inferenceEngine = new BehaviorInferenceEngine();
```

Replace the existing no-arg constructor so both constructors exist:

```java
    public CBOMOutputFile() {
        this(java.util.Collections.emptySet());
    }

    public CBOMOutputFile(@Nonnull Set<AuthContext.Kind> authSignals) {
        this.components = new HashMap<>();
        this.dependencies = new HashMap<>();
        this.authSignals = authSignals;
    }
```

Replace the behavior-emission block in `getBom()` (currently the `if (!this.aggregatedBehaviors.isEmpty()) { ... }` block, ~line 353-367) with:

```java
        // Experimental: attach the scan-wide crypto behavior summary to metadata.component.
        final Set<CryptoBehavior> behaviors =
                this.inferenceEngine.infer(this.aggregatedBehaviors, this.authSignals);
        if (!behaviors.isEmpty()) {
            final Component softwareComponent = new Component();
            softwareComponent.setType(Component.Type.APPLICATION);
            softwareComponent.setName(METADATA_COMPONENT_NAME);
            final String value =
                    behaviors.stream()
                            .map(CryptoBehavior::fullId)
                            .sorted()
                            .collect(Collectors.joining(","));
            final Property behaviorProperty = new Property();
            behaviorProperty.setName(CryptoBehaviorMapper.BEHAVIOR_PROPERTY_NAME);
            behaviorProperty.setValue(value);
            softwareComponent.setProperties(List.of(behaviorProperty));
            metadata.setComponent(softwareComponent);
        }
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `mvn test -pl output -Dtest=CryptoBehaviorMetadataTest,CryptoBehaviorMapperTest,CryptoBehaviorTaxonomyTest`
Expected: PASS. (`CryptoBehaviorMapperTest` is unaffected — the mapper is unchanged.)

- [ ] **Step 7: Commit**

```bash
mvn spotless:apply -pl output
git add output/src/main/java/com/ibm/output/IOutputFileFactory.java output/src/main/java/com/ibm/output/cyclondx/CBOMOutputFileFactory.java output/src/main/java/com/ibm/output/cyclondx/CBOMOutputFile.java output/src/test/java/com/ibm/output/cyclonedx/CryptoBehaviorMetadataTest.java
git commit -m "feat(output): run behavior inference at emission with comma-joined behavior output"
```

---

## Task 5: Auth-interface AST detection (java)

**Files:**
- Modify: `java/pom.xml` (add two test-scope dependencies)
- Create: `java/src/main/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceDetection.java`
- Create: `java/src/main/java/com/ibm/plugin/rules/detection/auth/AuthDetectionRules.java`
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/JavaDetectionRules.java`
- Create test file (analysis input): `java/src/test/files/rules/detection/auth/AuthInterfaceTestFile.java`
- Test: `java/src/test/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceDetectionTest.java`

**Interfaces:**
- Consumes: `AuthContext` (Task 1), `DetectionRuleBuilder`, `ValueActionFactory`, `IDetectionRule<Tree>`.
- Produces: `AuthInterfaceDetection.rules()` → `List<IDetectionRule<Tree>>`; `AuthDetectionRules.rules()` → `List<IDetectionRule<Tree>>` (wired into `JavaDetectionRules.rules()`).

**Detection contract:** `io.jsonwebtoken.Jwts#parser()` / `#parserBuilder()` (no args) → `AuthContext(Kind.JWT)`; `jakarta.servlet.http.HttpServletRequest#getUserPrincipal()` (no args) → `AuthContext(Kind.PRINCIPAL)`. All use `ValueActionFactory` + `.withoutParameters()` (the `SecureRandom.getInstanceStrong()` pattern).

- [ ] **Step 1: Add test dependencies to `java/pom.xml`**

In the `<dependencies>` block (next to the existing `bcprov-jdk18on` test dep), add:

```xml
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
            <version>0.12.6</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>jakarta.servlet</groupId>
            <artifactId>jakarta.servlet-api</artifactId>
            <version>6.0.0</version>
            <scope>test</scope>
        </dependency>
```

- [ ] **Step 2: Write the failing test + analysis input file**

Create the analysis input `java/src/test/files/rules/detection/auth/AuthInterfaceTestFile.java` (this is source *analyzed by* the test, not run):

```java
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;

class AuthInterfaceTestFile {
    void useJwt() {
        Jwts.parser();
    }

    Principal usePrincipal(HttpServletRequest request) {
        return request.getUserPrincipal();
    }
}
```

Create `java/src/test/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceDetectionTest.java` (header; asserts on the detection store's context since auth findings are contextual and report no issue):

```java
package com.ibm.plugin.rules.detection.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.context.AuthContext;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class AuthInterfaceDetectionTest extends TestBase {

    private final Set<AuthContext.Kind> observedKinds = EnumSet.noneOf(AuthContext.Kind.class);

    protected AuthInterfaceDetectionTest() {
        super(AuthDetectionRules.rules());
    }

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/auth/AuthInterfaceTestFile.java")
                .withChecks(this)
                .verifyNoIssues();

        assertThat(observedKinds)
                .contains(AuthContext.Kind.JWT, AuthContext.Kind.PRINCIPAL);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        // Auth findings are contextual: they carry an AuthContext and do not translate to a
        // crypto INode. Record the kind so the test can assert both interfaces were detected.
        assertThat(detectionStore.getDetectionValueContext())
                .as("finding %d must carry an AuthContext", findingId)
                .isInstanceOf(AuthContext.class);
        final AuthContext context = (AuthContext) detectionStore.getDetectionValueContext();
        observedKinds.add(context.kind());
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `mvn test -pl java -Dtest=AuthInterfaceDetectionTest`
Expected: FAIL — `AuthDetectionRules` / `AuthInterfaceDetection` do not exist (compile error).

- [ ] **Step 4: Write the detection rules**

Create `java/src/main/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceDetection.java` (header; mirror `SecureRandomGetInstance`):

```java
package com.ibm.plugin.rules.detection.auth;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class AuthInterfaceDetection {

    private static final IDetectionRule<Tree> JWT_PARSER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("io.jsonwebtoken.Jwts")
                    .forMethods("parser", "parserBuilder")
                    .shouldBeDetectedAs(new ValueActionFactory<>("JWT"))
                    .withoutParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.JWT))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SERVLET_PRINCIPAL =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("jakarta.servlet.http.HttpServletRequest")
                    .forMethods("getUserPrincipal")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PRINCIPAL"))
                    .withoutParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.PRINCIPAL))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    private AuthInterfaceDetection() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(JWT_PARSER, SERVLET_PRINCIPAL);
    }
}
```

Create `java/src/main/java/com/ibm/plugin/rules/detection/auth/AuthDetectionRules.java` (header; mirror `SSLDetectionRules`):

```java
package com.ibm.plugin.rules.detection.auth;

import com.ibm.engine.rule.IDetectionRule;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

/**
 * Phase 1 authentication/token interface detection. OAUTH and SAML kinds exist in {@link
 * com.ibm.engine.model.context.AuthContext.Kind} and are handled by the inference engine, but
 * their detection rules are deferred (design §9 / future work).
 */
public final class AuthDetectionRules {

    private AuthDetectionRules() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return Stream.of(AuthInterfaceDetection.rules().stream()).flatMap(i -> i).toList();
    }
}
```

- [ ] **Step 5: Wire into `JavaDetectionRules`**

Add the import and the stream entry:

```java
import com.ibm.plugin.rules.detection.auth.AuthDetectionRules;
```

```java
        return Stream.of(
                        JcaDetectionRules.rules().stream(),
                        BouncyCastleDetectionRules.rules().stream(),
                        SSLDetectionRules.rules().stream(),
                        AuthDetectionRules.rules().stream(),
                        SecureRandomGetInstance.rules().stream())
                .flatMap(i -> i)
                .toList();
```

- [ ] **Step 6: Run test to verify it passes**

Run: `mvn test -pl java -Dtest=AuthInterfaceDetectionTest`
Expected: PASS — `verifyNoIssues()` succeeds (auth findings report no issue) and both `JWT` and `PRINCIPAL` kinds are observed.

> If `verifyNoIssues()` fails because an auth finding unexpectedly translated to a reportable node, switch the assertion to `.verifyIssues()` only after adding the matching `// Noncompliant` markers; but the expected path is no issue, because auth findings carry no crypto value the `InventoryRule` reports on.

- [ ] **Step 7: Commit**

```bash
mvn spotless:apply -pl java
git add java/pom.xml java/src/main/java/com/ibm/plugin/rules/detection/auth/ java/src/main/java/com/ibm/plugin/rules/detection/JavaDetectionRules.java java/src/test/files/rules/detection/auth/ java/src/test/java/com/ibm/plugin/rules/detection/auth/
git commit -m "feat(java): detect JWT and servlet-principal auth interfaces as AuthContext signals"
```

---

## Task 6: `BehaviorEvidenceStore` + routing in `JavaBaseDetectionRule` (java)

**Files:**
- Create: `java/src/main/java/com/ibm/plugin/BehaviorEvidenceStore.java`
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/JavaBaseDetectionRule.java` (`update()`, ~line 100)
- Test: `java/src/test/java/com/ibm/plugin/BehaviorEvidenceStoreTest.java`

**Interfaces:**
- Consumes: `AuthContext` (Task 1), `IDetectionContext`.
- Produces: static `BehaviorEvidenceStore.recordFrom(IDetectionContext)` → `boolean` (records the kind and returns `true` iff it is an `AuthContext` with a non-`NONE` kind); `BehaviorEvidenceStore.getSignals()` → `Set<AuthContext.Kind>`; `BehaviorEvidenceStore.reset()`.

- [ ] **Step 1: Write the failing test**

Create `java/src/test/java/com/ibm/plugin/BehaviorEvidenceStoreTest.java` (header; package `com.ibm.plugin`):

```java
package com.ibm.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.engine.model.context.CipherContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class BehaviorEvidenceStoreTest {

    @BeforeEach
    void reset() {
        BehaviorEvidenceStore.reset();
    }

    @Test
    void recordsAuthContextKind() {
        final boolean recorded =
                BehaviorEvidenceStore.recordFrom(new AuthContext(AuthContext.Kind.JWT));
        assertThat(recorded).isTrue();
        assertThat(BehaviorEvidenceStore.getSignals()).containsExactly(AuthContext.Kind.JWT);
    }

    @Test
    void ignoresNonAuthContext() {
        final boolean recorded = BehaviorEvidenceStore.recordFrom(new CipherContext());
        assertThat(recorded).isFalse();
        assertThat(BehaviorEvidenceStore.getSignals()).isEmpty();
    }

    @Test
    void ignoresNoneKind() {
        final boolean recorded = BehaviorEvidenceStore.recordFrom(new AuthContext());
        assertThat(recorded).isFalse();
        assertThat(BehaviorEvidenceStore.getSignals()).isEmpty();
    }

    @Test
    void resetClearsSignals() {
        BehaviorEvidenceStore.recordFrom(new AuthContext(AuthContext.Kind.PRINCIPAL));
        BehaviorEvidenceStore.reset();
        assertThat(BehaviorEvidenceStore.getSignals()).isEmpty();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl java -Dtest=BehaviorEvidenceStoreTest`
Expected: FAIL — `BehaviorEvidenceStore` does not exist.

- [ ] **Step 3: Write minimal implementation**

Create `java/src/main/java/com/ibm/plugin/BehaviorEvidenceStore.java` (header; package `com.ibm.plugin`; mirrors the static `JavaAggregator` scan-store pattern):

```java
package com.ibm.plugin;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.engine.model.context.IDetectionContext;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Scan-wide accumulator of non-crypto contextual signals (design §4.3). Holds the set of detected
 * authentication-interface kinds. Written from {@link
 * com.ibm.plugin.rules.detection.JavaBaseDetectionRule} when it routes an {@link AuthContext}
 * finding; read by {@code ScannerManager} and passed into the output factory. Static and
 * reset per scan, mirroring {@link JavaAggregator}.
 */
public final class BehaviorEvidenceStore {

    private static Set<AuthContext.Kind> signals = EnumSet.noneOf(AuthContext.Kind.class);

    private BehaviorEvidenceStore() {
        // nothing
    }

    public static boolean recordFrom(@Nonnull IDetectionContext context) {
        if (context instanceof AuthContext authContext
                && authContext.kind() != AuthContext.Kind.NONE) {
            signals.add(authContext.kind());
            return true;
        }
        return false;
    }

    @Nonnull
    public static Set<AuthContext.Kind> getSignals() {
        return Collections.unmodifiableSet(signals);
    }

    public static void reset() {
        signals = EnumSet.noneOf(AuthContext.Kind.class);
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn test -pl java -Dtest=BehaviorEvidenceStoreTest`
Expected: PASS (4 tests).

- [ ] **Step 5: Route auth findings in `JavaBaseDetectionRule.update()`**

Add the import:

```java
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.plugin.BehaviorEvidenceStore;
```

Replace the body of `update(...)` so auth findings are captured into the store (only in the inventory pass) and skip crypto translation/reporting:

```java
    @Override
    public void update(@Nonnull Finding<JavaCheck, Tree, Symbol, JavaFileScannerContext> finding) {
        final IDetectionContext context =
                finding.detectionStore().getDetectionValueContext();
        if (isInventory && BehaviorEvidenceStore.recordFrom(context)) {
            // Contextual auth signal captured scan-wide; do not translate to a crypto node
            // or report it as an inventory finding.
            return;
        }
        final List<INode> nodes = javaTranslationProcess.initiate(finding.detectionStore());
        if (isInventory) {
            JavaAggregator.addNodes(nodes);
        }
        // report
        this.report(finding.getMarkerTree(), nodes)
                .forEach(
                        issue ->
                                finding.detectionStore()
                                        .getScanContext()
                                        .reportIssue(this, issue.tree(), issue.message()));
    }
```

- [ ] **Step 6: Run tests to verify nothing regressed**

Run: `mvn test -pl java`
Expected: PASS — all existing java detection tests still green (crypto findings are unaffected; `TestBase` overrides `update()` so the routing does not perturb detection tests), plus `BehaviorEvidenceStoreTest` and `AuthInterfaceDetectionTest`.

- [ ] **Step 7: Commit**

```bash
mvn spotless:apply -pl java
git add java/src/main/java/com/ibm/plugin/BehaviorEvidenceStore.java java/src/main/java/com/ibm/plugin/rules/detection/JavaBaseDetectionRule.java java/src/test/java/com/ibm/plugin/BehaviorEvidenceStoreTest.java
git commit -m "feat(java): route AuthContext findings into scan-wide BehaviorEvidenceStore"
```

---

## Task 7: Thread evidence into output emission via `ScannerManager` (plugin)

**Files:**
- Modify: `sonar-cryptography-plugin/src/main/java/com/ibm/plugin/ScannerManager.java` (`getOutputFile()`, `reset()`)
- Test: `sonar-cryptography-plugin/src/test/java/com/ibm/plugin/ScannerManagerBehaviorWiringTest.java`

**Interfaces:**
- Consumes: `BehaviorEvidenceStore.getSignals()` / `.reset()` (Task 6, package `com.ibm.plugin`, no import needed — split package); `IOutputFileFactory.createOutputFormat(nodes, authSignals)` (Task 4).
- Produces: `ScannerManager.getOutputFile()` now forwards the evidence store's signals to the factory; `ScannerManager.reset()` also resets the store.

- [ ] **Step 1: Write the failing test**

Create `sonar-cryptography-plugin/src/test/java/com/ibm/plugin/ScannerManagerBehaviorWiringTest.java` (header; package `com.ibm.plugin`; a capturing factory records the signals it receives):

```java
package com.ibm.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.mapper.model.INode;
import com.ibm.output.IOutputFile;
import com.ibm.output.IOutputFileFactory;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ScannerManagerBehaviorWiringTest {

    private Set<AuthContext.Kind> captured;

    private final IOutputFileFactory capturingFactory =
            new IOutputFileFactory() {
                @Nonnull
                @Override
                public IOutputFile createOutputFormat(
                        @Nonnull List<INode> nodes,
                        @Nonnull Set<AuthContext.Kind> authSignals) {
                    captured = authSignals;
                    return format -> {
                        // no-op IOutputFile
                    };
                }
            };

    @BeforeEach
    @AfterEach
    void resetStores() {
        BehaviorEvidenceStore.reset();
        JavaAggregator.reset();
    }

    @Test
    void forwardsEvidenceSignalsToFactory() {
        BehaviorEvidenceStore.recordFrom(new AuthContext(AuthContext.Kind.JWT));
        new ScannerManager(capturingFactory).getOutputFile();
        assertThat(captured).containsExactly(AuthContext.Kind.JWT);
    }

    @Test
    void resetClearsEvidenceStore() {
        BehaviorEvidenceStore.recordFrom(new AuthContext(AuthContext.Kind.PRINCIPAL));
        new ScannerManager(capturingFactory).reset();
        assertThat(BehaviorEvidenceStore.getSignals()).isEmpty();
    }
}
```

> `IOutputFile` is a single-method interface (`saveTo(...)`); confirm the lambda `format -> {}` matches its signature. If `IOutputFile` has a different single abstract method, implement it as an anonymous class returning nothing. Check `output/src/main/java/com/ibm/output/IOutputFile.java` for the exact method.

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl sonar-cryptography-plugin -Dtest=ScannerManagerBehaviorWiringTest`
Expected: FAIL — `getOutputFile()` still calls the single-arg `createOutputFormat`, so the capturing factory (two-arg override) is never satisfied / `captured` stays null.

- [ ] **Step 3: Modify `ScannerManager`**

Update `getOutputFile()` to pass the evidence signals, and `reset()` to clear the store:

```java
    @Nonnull
    public IOutputFile getOutputFile() {
        return Optional.ofNullable(this.outputFileFactory)
                .orElse(IOutputFileFactory.DEFAULT)
                .createOutputFormat(getAggregatedNodes(), BehaviorEvidenceStore.getSignals());
    }
```

```java
    public void reset() {
        JavaAggregator.reset();
        PythonAggregator.reset();
        GoAggregator.reset();
        BehaviorEvidenceStore.reset();
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn test -pl sonar-cryptography-plugin -Dtest=ScannerManagerBehaviorWiringTest`
Expected: PASS (2 tests).

- [ ] **Step 5: Full build**

Run: `mvn clean package`
Expected: BUILD SUCCESS — all modules compile, Spotless/Checkstyle pass, every module's tests green. This exercises the full pipeline end-to-end.

- [ ] **Step 6: Commit**

```bash
mvn spotless:apply
git add sonar-cryptography-plugin/src/main/java/com/ibm/plugin/ScannerManager.java sonar-cryptography-plugin/src/test/java/com/ibm/plugin/ScannerManagerBehaviorWiringTest.java
git commit -m "feat(plugin): forward auth evidence signals from ScannerManager into CBOM output"
```

---

## Self-Review Notes (for the implementer)

- **Spec coverage:** AuthContext (§4.1 → Task 1); CryptoBehavior additions (§4.2/§4.4 → Task 2); inference engine two-tier gating (§4.4/§5 → Task 3); emission + gate restructure (§4.5/§6 → Task 4); AST auth detection (§4.2 → Task 5); evidence store + routing (§4.3 → Task 6); ScannerManager threading (§4 flow → Task 7). Phase 2 (§9) and OAUTH/SAML detection are explicitly deferred, not implemented.
- **Package spelling:** production behavior package is `com.ibm.output.cyclondx.behavior` (no `e` in `cyclondx`); tests live under `com.ibm.output.cyclonedx.behavior` (with `e`). This inconsistency is pre-existing — match each file to its existing neighbors.
- **Gating regression to watch:** Task 4 drops MAC-only `authenticates` from the `cbomkit:crypto:behavior` value. The `CryptoBehaviorMetadataTest` update in Task 4 is the guard; do not skip it.
