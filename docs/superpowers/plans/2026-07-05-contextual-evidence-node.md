# Contextual Evidence Node Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `BehaviorEvidenceStore` sidecar with a generic `ContextualEvidence` node that carries auth-interface evidence through the existing per-language detection→translation→aggregation→output pipeline.

**Architecture:** Auth findings (already produced by the Phase-1 detection rules) are translated to a generic `ContextualEvidence` INode by a per-language context translator, flow through the normal `Aggregator → ScannerManager → CBOMOutputFile.add()` pipe, and are collected at `add()` into the inference input. The Java-only static store, its routing branch, the factory-signature change, and the `ScannerManager` threading are all removed.

**Tech Stack:** Java 17, Maven multi-module, sonar-java `CheckVerifier`, JUnit 5 + AssertJ, CycloneDX model.

## Global Constraints

- Java 17; module boundaries: `engine` → `mapper`/`output` → `java` → `sonar-cryptography-plugin`.
- Apache 2.0 license header in every new `.java` file (copy verbatim from a neighbor in the same module). Run `mvn spotless:apply` before committing.
- Property name stays `cbomkit:crypto:behavior`; its value is a comma-joined list of behavior ids. The two-tier gating inference and its output are unchanged from `2026-07-04-crypto-behavior-context-layer-design.md`.
- Phase 1 detection scope stays Java-only (JWT + servlet principal). `AuthContext.Kind` in engine remains the single evidence vocabulary.
- Use `-am` on module test commands so upstream modules are rebuilt from source (avoids stale local-repo installs).

---

## File Structure

- `mapper/.../model/ContextualEvidence.java` — CREATE — generic IR evidence node (`extends Property`).
- `java/.../translation/translator/contexts/JavaAuthContextTranslator.java` — CREATE — `AuthContext` finding → `ContextualEvidence`.
- `java/.../translation/translator/JavaTranslator.java` — MODIFY — one dispatch branch for `AuthContext`.
- `java/.../rules/detection/auth/AuthInterfaceDetectionTest.java` — MODIFY — assert the translated `ContextualEvidence` node.
- `output/.../cyclondx/CBOMOutputFile.java` — MODIFY — no-arg ctor; collect `authSignals` from nodes in `add()`.
- `output/.../IOutputFileFactory.java` + `cyclondx/CBOMOutputFileFactory.java` — REVERT — single-arg `createOutputFormat(nodes)`.
- `output/.../cyclonedx/CryptoBehaviorMetadataTest.java` — MODIFY — auth case builds a `ContextualEvidence` node.
- `java/.../rules/detection/JavaBaseDetectionRule.java` — REVERT — remove the auth-routing branch.
- `sonar-cryptography-plugin/.../ScannerManager.java` — REVERT — single-arg call; no store reset.
- `java/.../plugin/BehaviorEvidenceStore.java` (+ test) and `sonar-cryptography-plugin/.../ScannerManagerBehaviorWiringTest.java` — DELETE.

---

## Task 1: `ContextualEvidence` IR node (mapper)

**Files:**
- Create: `mapper/src/main/java/com/ibm/mapper/model/ContextualEvidence.java`
- Test: `mapper/src/test/java/com/ibm/mapper/model/ContextualEvidenceTest.java`

**Interfaces:**
- Consumes: `Property` (abstract `IProperty` base), `DetectionLocation`, `INode`.
- Produces: `ContextualEvidence(String identifier, DetectionLocation location)`; `String identifier()`; `asString()` → identifier; `getKind()` → `ContextualEvidence.class`; `deepCopy()`; value-based `equals`/`hashCode`.

- [ ] **Step 1: Write the failing test**

Create `mapper/src/test/java/com/ibm/mapper/model/ContextualEvidenceTest.java` (copy the license header from `mapper/src/main/java/com/ibm/mapper/model/Seed.java`):

```java
package com.ibm.mapper.model;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Collections;
import org.junit.jupiter.api.Test;

class ContextualEvidenceTest {

    private final IBundle bundle = () -> "Test";
    private final DetectionLocation location =
            new DetectionLocation("Test.java", 1, 1, Collections.emptyList(), bundle);

    @Test
    void carriesIdentifierAndKind() {
        final ContextualEvidence evidence = new ContextualEvidence("JWT", location);
        assertThat(evidence.identifier()).isEqualTo("JWT");
        assertThat(evidence.asString()).isEqualTo("JWT");
        assertThat(evidence.getKind()).isEqualTo(ContextualEvidence.class);
        assertThat(evidence.is(ContextualEvidence.class)).isTrue();
    }

    @Test
    void deepCopyEqualsOriginal() {
        final ContextualEvidence evidence = new ContextualEvidence("PRINCIPAL", location);
        assertThat(evidence.deepCopy()).isEqualTo(evidence);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl mapper -am -Dtest=ContextualEvidenceTest`
Expected: FAIL — `ContextualEvidence` does not exist (compilation error).

- [ ] **Step 3: Write minimal implementation**

Create `mapper/src/main/java/com/ibm/mapper/model/ContextualEvidence.java` (copy the header from `Seed.java`):

```java
package com.ibm.mapper.model;

import com.ibm.mapper.utils.DetectionLocation;
import java.util.Objects;
import javax.annotation.Nonnull;

/**
 * A detected contextual fact about the scanned code (e.g. an authentication interface such as JWT
 * or a servlet principal). NOT a cryptographic asset: the mapper model is the scan's intermediate
 * representation, not a crypto-asset registry. The output layer interprets this node to inform the
 * software-level behavior taxonomy and never emits it as a CBOM component. Generic by design so
 * future non-auth evidence reuses it. The {@code identifier} is a stable token (currently an {@code
 * AuthContext.Kind} name, e.g. "JWT").
 */
public final class ContextualEvidence extends Property {
    @Nonnull private final String identifier;

    public ContextualEvidence(
            @Nonnull String identifier, @Nonnull DetectionLocation detectionLocation) {
        super(ContextualEvidence.class, detectionLocation);
        this.identifier = identifier;
    }

    private ContextualEvidence(@Nonnull ContextualEvidence evidence) {
        super(evidence.type, evidence.detectionLocation, evidence.children);
        this.identifier = evidence.identifier;
    }

    @Nonnull
    public String identifier() {
        return identifier;
    }

    @Nonnull
    @Override
    public String asString() {
        return identifier;
    }

    @Nonnull
    @Override
    public INode deepCopy() {
        ContextualEvidence copy = new ContextualEvidence(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (!(object instanceof ContextualEvidence evidence)) return false;
        if (!super.equals(object)) return false;
        return Objects.equals(identifier, evidence.identifier);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), identifier);
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn test -pl mapper -am -Dtest=ContextualEvidenceTest`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
mvn spotless:apply -pl mapper
git add mapper/src/main/java/com/ibm/mapper/model/ContextualEvidence.java mapper/src/test/java/com/ibm/mapper/model/ContextualEvidenceTest.java
git commit -m "feat(mapper): add generic ContextualEvidence IR node"
```

---

## Task 2: `JavaAuthContextTranslator` + pipeline wiring (java)

**Files:**
- Create: `java/src/main/java/com/ibm/plugin/translation/translator/contexts/JavaAuthContextTranslator.java`
- Modify: `java/src/main/java/com/ibm/plugin/translation/translator/JavaTranslator.java` (dispatch chain, ~line 149-156)
- Modify: `java/src/test/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceDetectionTest.java` (`asserts()`)

**Interfaces:**
- Consumes: `ContextualEvidence` (Task 1); `AuthContext` (engine); `IContextTranslation<Tree>`.
- Produces: `JavaAuthContextTranslator` — an `AuthContext(kind)` finding translates to `ContextualEvidence(kind.name(), location)`; `kind == NONE` → empty.

This task drives its verification through the existing detection test: because `TestBase.update()` runs the full `translate → reorganize → enrich` pipeline before calling `asserts()`, asserting the `ContextualEvidence` node appears also proves it survives those stages inert (the passthrough concern).

- [ ] **Step 1: Update the detection test to expect the node**

In `AuthInterfaceDetectionTest.java`, add the import `com.ibm.mapper.model.ContextualEvidence` (next to the existing `com.ibm.mapper.model.INode` import) and replace the `asserts(...)` body with:

```java
    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValueContext())
                .as("finding %d must carry an AuthContext", findingId)
                .isInstanceOf(AuthContext.class);
        final AuthContext context = (AuthContext) detectionStore.getDetectionValueContext();

        // Auth findings now translate to a generic ContextualEvidence node and ride the normal
        // pipeline (translate + reorganize + enrich). Asserting the node here also proves it
        // passes those stages inert.
        final ContextualEvidence evidence =
                (ContextualEvidence)
                        nodes.stream()
                                .filter(n -> n.is(ContextualEvidence.class))
                                .findFirst()
                                .orElseThrow();
        assertThat(evidence.identifier())
                .as("finding %d node identifier should match the auth kind", findingId)
                .isEqualTo(context.kind().name());
        observedKinds.add(context.kind());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl java -am -Dtest=AuthInterfaceDetectionTest`
Expected: FAIL — no `ContextualEvidence` node is produced yet (`orElseThrow` → `NoSuchElementException`), because `JavaTranslator` has no `AuthContext` branch.

- [ ] **Step 3: Write the translator**

Create `java/src/main/java/com/ibm/plugin/translation/translator/contexts/JavaAuthContextTranslator.java` (copy the header from `JavaProtocolContextTranslator.java` in the same package):

```java
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.AuthContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.ContextualEvidence;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaAuthContextTranslator implements IContextTranslation<Tree> {

    @Nonnull
    @Override
    public Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        final AuthContext.Kind kind = ((AuthContext) detectionContext).kind();
        if (kind == AuthContext.Kind.NONE) {
            return Optional.empty();
        }
        return Optional.of(new ContextualEvidence(kind.name(), detectionLocation));
    }
}
```

- [ ] **Step 4: Wire the translator into `JavaTranslator`**

Add the imports:

```java
import com.ibm.engine.model.context.AuthContext;
import com.ibm.plugin.translation.translator.contexts.JavaAuthContextTranslator;
```

In the dispatch chain, replace the closing `ProtocolContext` branch + trailing return:

```java
        } else if (detectionValueContext.is(ProtocolContext.class)) {
            final JavaProtocolContextTranslator javaProtocolContextTranslator =
                    new JavaProtocolContextTranslator();
            return javaProtocolContextTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        }
        return Optional.empty();
```

with:

```java
        } else if (detectionValueContext.is(ProtocolContext.class)) {
            final JavaProtocolContextTranslator javaProtocolContextTranslator =
                    new JavaProtocolContextTranslator();
            return javaProtocolContextTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);

            // authentication interface (contextual evidence)
        } else if (detectionValueContext.is(AuthContext.class)) {
            final JavaAuthContextTranslator javaAuthContextTranslator =
                    new JavaAuthContextTranslator();
            return javaAuthContextTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        }
        return Optional.empty();
```

- [ ] **Step 5: Run test to verify it passes**

Run: `mvn test -pl java -am -Dtest=AuthInterfaceDetectionTest`
Expected: PASS — both `JWT` and `PRINCIPAL` findings translate to `ContextualEvidence` nodes with matching identifiers, and `verifyNoIssues()` still holds (`InventoryRule` only reports `Algorithm`/`Protocol`/`Key`).

- [ ] **Step 6: Commit**

```bash
mvn spotless:apply -pl java
git add java/src/main/java/com/ibm/plugin/translation/translator/contexts/JavaAuthContextTranslator.java java/src/main/java/com/ibm/plugin/translation/translator/JavaTranslator.java java/src/test/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceDetectionTest.java
git commit -m "feat(java): translate AuthContext findings to ContextualEvidence nodes"
```

---

## Task 3: Collect evidence at output; remove the sidecar (output + java + plugin)

This task flips the channel atomically: the output layer starts collecting evidence from `ContextualEvidence` nodes, and the sidecar (store + routing + factory arg + threading) is removed. It spans modules because the factory signature is shared, so it lands as one green build.

**Files:**
- Modify: `output/src/main/java/com/ibm/output/cyclondx/CBOMOutputFile.java`
- Revert: `output/src/main/java/com/ibm/output/IOutputFileFactory.java`, `output/src/main/java/com/ibm/output/cyclondx/CBOMOutputFileFactory.java`
- Modify: `output/src/test/java/com/ibm/output/cyclonedx/CryptoBehaviorMetadataTest.java`
- Revert: `java/src/main/java/com/ibm/plugin/rules/detection/JavaBaseDetectionRule.java`
- Revert: `sonar-cryptography-plugin/src/main/java/com/ibm/plugin/ScannerManager.java`
- Delete: `java/src/main/java/com/ibm/plugin/BehaviorEvidenceStore.java`, `java/src/test/java/com/ibm/plugin/BehaviorEvidenceStoreTest.java`, `sonar-cryptography-plugin/src/test/java/com/ibm/plugin/ScannerManagerBehaviorWiringTest.java`

**Interfaces:**
- Consumes: `ContextualEvidence` (Task 1); `BehaviorInferenceEngine`, `CryptoBehavior`, `AuthContext.Kind` (existing).
- Produces: `IOutputFileFactory.createOutputFormat(List<INode> nodes)` (single-arg, restored); `CBOMOutputFile()` no-arg ctor that self-collects auth signals from `ContextualEvidence` nodes during `add()`.

- [ ] **Step 1: Update the metadata test to drive node-based collection**

In `CryptoBehaviorMetadataTest.java`: remove the imports `com.ibm.engine.model.context.AuthContext` and `java.util.Set`; add `import com.ibm.mapper.model.ContextualEvidence;`. Replace the `authInterfaceUnlocksAuthenticatesAndValidatesToken` test with the node-based version (uses the no-arg `bomOf` helper):

```java
    @Test
    void authInterfaceUnlocksAuthenticatesAndValidatesToken() {
        final AES aes = new AES(loc);
        aes.put(new Encrypt(loc));
        final Bom bom = bomOf(List.of(aes, new ContextualEvidence("JWT", loc)));

        final Property property = bom.getMetadata().getComponent().getProperties().get(0);
        assertThat(property.getValue())
                .contains("security:cryptography:authenticates")
                .contains("security:cryptography:validatesToken")
                .contains("security:cryptography:encryptsData");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl output -am -Dtest=CryptoBehaviorMetadataTest`
Expected: FAIL — `CBOMOutputFile.add()` does not yet collect `ContextualEvidence`, so `authenticates`/`validatesToken` are absent (also the removed `Set`/`AuthContext` imports would be unused). Compilation may fail first on the deleted two-arg constructor usage — that is expected; proceed.

- [ ] **Step 3: Modify `CBOMOutputFile` — no-arg ctor + node collection**

Add the import `com.ibm.mapper.model.ContextualEvidence` (near the other `com.ibm.mapper.model.*` imports). Replace the field + constructor block:

```java
    @Nonnull private final Set<AuthContext.Kind> authSignals;

    @Nonnull
    private final BehaviorInferenceEngine inferenceEngine = new BehaviorInferenceEngine();

    // Intentional simplification of spec §4.4: use a fixed name because no scanned-software
    // name is plumbed into getBom(); the ideal value would be the scanned project name.
    private static final String METADATA_COMPONENT_NAME = "application";

    public CBOMOutputFile() {
        this(java.util.Collections.emptySet());
    }

    public CBOMOutputFile(@Nonnull Set<AuthContext.Kind> authSignals) {
        this.components = new HashMap<>();
        this.dependencies = new HashMap<>();
        this.authSignals = authSignals;
    }
```

with:

```java
    @Nonnull
    private final Set<AuthContext.Kind> authSignals = EnumSet.noneOf(AuthContext.Kind.class);

    @Nonnull
    private final BehaviorInferenceEngine inferenceEngine = new BehaviorInferenceEngine();

    // Intentional simplification of spec §4.4: use a fixed name because no scanned-software
    // name is plumbed into getBom(); the ideal value would be the scanned project name.
    private static final String METADATA_COMPONENT_NAME = "application";

    public CBOMOutputFile() {
        this.components = new HashMap<>();
        this.dependencies = new HashMap<>();
    }
```

In `add(...)`, insert the evidence branch immediately before the `else if (node.hasChildren())` fallback:

```java
                    } else if (node instanceof ContextualEvidence evidence) {
                        recordContextualEvidence(evidence);
                    } else if (node.hasChildren()) {
```

Add the helper method (place it just after the `add(...)` method):

```java
    private void recordContextualEvidence(@Nonnull ContextualEvidence evidence) {
        // ContextualEvidence carries a generic identifier; map the ones that name an auth
        // interface back to the typed vocabulary. Unknown identifiers are not auth signals; skip.
        try {
            this.authSignals.add(AuthContext.Kind.valueOf(evidence.identifier()));
        } catch (IllegalArgumentException ignored) {
            // not an auth-interface evidence identifier we model
        }
    }
```

(`getBom()` is unchanged — it already calls `inferenceEngine.infer(this.aggregatedBehaviors, this.authSignals)`.)

- [ ] **Step 4: Revert `IOutputFileFactory` and `CBOMOutputFileFactory` to single-arg**

`output/src/main/java/com/ibm/output/IOutputFileFactory.java` — restore:

```java
package com.ibm.output;

import com.ibm.mapper.model.INode;
import com.ibm.output.cyclondx.CBOMOutputFileFactory;
import java.util.List;
import javax.annotation.Nonnull;

public interface IOutputFileFactory {
    public static IOutputFileFactory DEFAULT = new CBOMOutputFileFactory();

    @Nonnull
    IOutputFile createOutputFormat(@Nonnull List<INode> nodes);
}
```

`output/src/main/java/com/ibm/output/cyclondx/CBOMOutputFileFactory.java` — restore:

```java
package com.ibm.output.cyclondx;

import com.ibm.mapper.model.INode;
import com.ibm.output.IOutputFileFactory;
import java.util.List;
import javax.annotation.Nonnull;

public class CBOMOutputFileFactory implements IOutputFileFactory {
    @Nonnull
    @Override
    public CBOMOutputFile createOutputFormat(@Nonnull List<INode> nodes) {
        CBOMOutputFile outputFile = new CBOMOutputFile();
        outputFile.add(nodes);
        return outputFile;
    }
}
```

- [ ] **Step 5: Revert `JavaBaseDetectionRule.update()` and `ScannerManager`**

`JavaBaseDetectionRule.java` — remove the imports `com.ibm.engine.model.context.IDetectionContext` and `com.ibm.plugin.BehaviorEvidenceStore`, and restore `update(...)`:

```java
    @Override
    public void update(@Nonnull Finding<JavaCheck, Tree, Symbol, JavaFileScannerContext> finding) {
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

`ScannerManager.java` — restore `getOutputFile()` and `reset()`:

```java
    @Nonnull
    public IOutputFile getOutputFile() {
        return Optional.ofNullable(this.outputFileFactory)
                .orElse(IOutputFileFactory.DEFAULT)
                .createOutputFormat(getAggregatedNodes());
    }
```

```java
    public void reset() {
        JavaAggregator.reset();
        PythonAggregator.reset();
        GoAggregator.reset();
    }
```

- [ ] **Step 6: Delete the sidecar files**

```bash
git rm java/src/main/java/com/ibm/plugin/BehaviorEvidenceStore.java \
       java/src/test/java/com/ibm/plugin/BehaviorEvidenceStoreTest.java \
       sonar-cryptography-plugin/src/test/java/com/ibm/plugin/ScannerManagerBehaviorWiringTest.java
```

- [ ] **Step 7: Run the output test, then the full build**

Run: `mvn test -pl output -am -Dtest=CryptoBehaviorMetadataTest`
Expected: PASS — `authInterfaceUnlocksAuthenticatesAndValidatesToken` sees the gated behaviors; the exact-value `aggregatesBehaviorsOfWholeScanOntoMetadataComponent` still matches (unchanged).

Run: `mvn spotless:apply` then `mvn clean package`
Expected: BUILD SUCCESS across all 11 modules; all tests green; no references to `BehaviorEvidenceStore` remain.

- [ ] **Step 8: Commit**

```bash
git add output/src/main/java/com/ibm/output/IOutputFileFactory.java \
        output/src/main/java/com/ibm/output/cyclondx/CBOMOutputFileFactory.java \
        output/src/main/java/com/ibm/output/cyclondx/CBOMOutputFile.java \
        output/src/test/java/com/ibm/output/cyclonedx/CryptoBehaviorMetadataTest.java \
        java/src/main/java/com/ibm/plugin/rules/detection/JavaBaseDetectionRule.java \
        sonar-cryptography-plugin/src/main/java/com/ibm/plugin/ScannerManager.java
git commit -m "refactor: collect contextual evidence from IR nodes, remove BehaviorEvidenceStore sidecar"
```

---

## Self-Review Notes (for the implementer)

- **Spec coverage:** `ContextualEvidence` node (§4.1 → Task 1); per-language translator + `JavaTranslator` wiring (§4.2 → Task 2); `add()` collection + `recordContextualEvidence` + guarded `valueOf` (§4.3 → Task 3); all five reverts in §5 → Task 3; passthrough test (§7) folded into Task 2's detection test (the full `initiate()` pipeline runs there).
- **Vocabulary bridge:** the node stores `AuthContext.Kind.name()`; `recordContextualEvidence` maps it back via guarded `valueOf`. `BehaviorInferenceEngine` stays typed on `AuthContext.Kind` and its tests are untouched.
- **Package spelling:** production behavior package is `com.ibm.output.cyclondx.behavior` (no `e`); output tests live under `com.ibm.output.cyclonedx` (with `e`). Match each file to its neighbors.
- **`add()` branch order:** the `ContextualEvidence` branch must precede `else if (node.hasChildren())`, or the leaf node is dropped.
- **Auth-only scans count as results** (design §3): `ContextualEvidence` nodes are in `getAggregatedNodes()`; a scan with only an auth interface emits behavior metadata. Intended, not filtered.
