# Detection Rule Set Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the per-class `Memoize.of(...)` boilerplate in every detection-rule class with an abstract base plus a `RuleSets` registry that owns the cache, so no code path can rebuild a rule subtree.

**Architecture:** Two abstract bases and one registry live in the `engine` module, package `com.ibm.engine.rule`. A rule class extends a base and implements only `buildRules()`, which is `protected` and therefore callable only from inside `com.ibm.engine.rule`. Callers use `RuleSets.rulesOf(SomeRules.class)`. The no-argument path is cached in a `ClassValue`; the context-parameterized path is cached in a `ConcurrentHashMap` keyed by class plus contexts, which requires `equals`/`hashCode` on the detection-context classes.

**Tech Stack:** Java 17, Maven multi-module, JUnit 5, AssertJ, Spotless (Google Java Format, AOSP style), Checkstyle.

**Spec:** `docs/superpowers/specs/2026-08-20-detection-rule-set-registry-design.md`

## Global Constraints

- Java 17. No new third-party dependencies.
- Every new `.java` file needs the Apache 2.0 header. Run `mvn spotless:apply` before every commit; it inserts the header and formats the file.
- Checkstyle rules that matter here: no unused imports, `@Override` required, private constructor on utility classes.
- Package for all new engine classes: `com.ibm.engine.rule`.
- Tree type per module (verified): `java` uses `org.sonar.plugins.java.api.tree.Tree`, `python` uses `org.sonar.plugins.python.api.tree.Tree`, `go` uses `org.sonar.plugins.go.api.Tree`, `csharp` uses `com.ibm.engine.language.csharp.tree.CSharpTree`. **Do not change any tree type**; copy the one already imported in the file you edit.
- `RuleGraphMemoizationTest` must stay green and its printed count must be at or below 2,563.
- Known baseline: `SecureRandomGetInstanceTest` in the `java` module fails on pristine `main` in some environments. A failure there is pre-existing, not a regression.
- If a build truncates `JsonCipherSuites.java`, restore it with `git checkout -- <path>` before committing.
- Branch: `refactor/detection-rule-set-registry`.

---

### Task 1: Rule-set bases and the no-argument registry

**Files:**
- Create: `engine/src/main/java/com/ibm/engine/rule/DetectionRuleSet.java`
- Create: `engine/src/main/java/com/ibm/engine/rule/ContextualDetectionRuleSet.java`
- Create: `engine/src/main/java/com/ibm/engine/rule/RuleSets.java`
- Test: `engine/src/test/java/com/ibm/engine/rule/RuleSetsTest.java`

**Interfaces:**
- Consumes: `com.ibm.engine.rule.IDetectionRule<T>` (exists), `com.ibm.engine.model.context.IDetectionContext` (exists).
- Produces:
  - `abstract class DetectionRuleSet<T>` with `protected abstract List<IDetectionRule<T>> buildRules()`
  - `abstract class ContextualDetectionRuleSet<T> extends DetectionRuleSet<T>` with `protected abstract List<IDetectionRule<T>> buildRules(List<IDetectionContext> contexts)` and `protected static IDetectionContext contextAt(List<IDetectionContext> contexts, int index)`
  - `static <T> List<IDetectionRule<T>> RuleSets.rulesOf(Class<? extends DetectionRuleSet<T>> type)`

- [ ] **Step 1: Write the failing test**

Create `engine/src/test/java/com/ibm/engine/rule/RuleSetsTest.java`:

```java
package com.ibm.engine.rule;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

class RuleSetsTest {

    /** Counts how often each set was actually built, so we can prove the cache works. */
    static final AtomicInteger LEAF_BUILDS = new AtomicInteger();

    static final class LeafRules extends DetectionRuleSet<Object> {
        @Nonnull
        @Override
        protected List<IDetectionRule<Object>> buildRules() {
            LEAF_BUILDS.incrementAndGet();
            return List.of();
        }
    }

    /** Builds by asking the registry for another set — the recursion the real rules do. */
    static final class ParentRules extends DetectionRuleSet<Object> {
        @Nonnull
        @Override
        protected List<IDetectionRule<Object>> buildRules() {
            return RuleSets.rulesOf(LeafRules.class);
        }
    }

    static final class NoDefaultConstructor extends DetectionRuleSet<Object> {
        NoDefaultConstructor(int unused) {
            // deliberately has no no-arg constructor
        }

        @Nonnull
        @Override
        protected List<IDetectionRule<Object>> buildRules() {
            return List.of();
        }
    }

    @Test
    void returnsTheSameListInstanceOnEveryCall() {
        assertThat(RuleSets.rulesOf(LeafRules.class)).isSameAs(RuleSets.rulesOf(LeafRules.class));
    }

    @Test
    void buildsEachSetOnlyOnce() {
        int before = LEAF_BUILDS.get();
        RuleSets.rulesOf(LeafRules.class);
        RuleSets.rulesOf(LeafRules.class);
        RuleSets.rulesOf(LeafRules.class);
        assertThat(LEAF_BUILDS.get() - before).isLessThanOrEqualTo(1);
    }

    @Test
    void supportsASetThatBuildsByAskingForAnotherSet() {
        assertThat(RuleSets.rulesOf(ParentRules.class))
                .isSameAs(RuleSets.rulesOf(LeafRules.class));
    }

    @Test
    void returnsAnImmutableList() {
        assertThatThrownBy(() -> RuleSets.rulesOf(LeafRules.class).add(null))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void explainsItselfWhenTheClassHasNoNoArgConstructor() {
        assertThatThrownBy(() -> RuleSets.rulesOf(NoDefaultConstructor.class))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no-argument constructor");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mvn test -pl engine -Dtest=RuleSetsTest`
Expected: compilation failure — `DetectionRuleSet`, `RuleSets` do not exist.

- [ ] **Step 3: Write the two bases**

`engine/src/main/java/com/ibm/engine/rule/DetectionRuleSet.java`:

```java
package com.ibm.engine.rule;

import java.util.List;
import javax.annotation.Nonnull;

/**
 * A named group of detection rules. Subclasses only describe how to build their rules; the
 * caching is owned by {@link RuleSets}, which is the only way to read them.
 *
 * <p>{@code buildRules()} is {@code protected} on purpose: nothing outside this package can call
 * it, so no caller can rebuild a subtree that is meant to be shared (see issue #476).
 */
public abstract class DetectionRuleSet<T> {

    protected DetectionRuleSet() {
        // only subclasses
    }

    @Nonnull
    protected abstract List<IDetectionRule<T>> buildRules();
}
```

`engine/src/main/java/com/ibm/engine/rule/ContextualDetectionRuleSet.java`:

```java
package com.ibm.engine.rule;

import com.ibm.engine.model.context.IDetectionContext;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * A rule set whose rules depend on one or more detection contexts. Callers reach it through
 * {@link RuleSets#rulesOf(Class, IDetectionContext...)}, which caches per class <em>and</em>
 * context.
 *
 * <p>The context list is positional and may contain {@code null} elements, which mean "use the
 * default for that position". Use {@link #contextAt(List, int)} to read it.
 */
public abstract class ContextualDetectionRuleSet<T> extends DetectionRuleSet<T> {

    protected ContextualDetectionRuleSet() {
        // only subclasses
    }

    @Nonnull
    protected abstract List<IDetectionRule<T>> buildRules(
            @Nonnull List<IDetectionContext> contexts);

    @Nonnull
    @Override
    protected final List<IDetectionRule<T>> buildRules() {
        return buildRules(List.of());
    }

    @Nullable
    protected static IDetectionContext contextAt(
            @Nonnull List<IDetectionContext> contexts, int index) {
        return index < contexts.size() ? contexts.get(index) : null;
    }
}
```

- [ ] **Step 4: Write the registry with the no-argument path only**

`engine/src/main/java/com/ibm/engine/rule/RuleSets.java`:

```java
package com.ibm.engine.rule;

import java.lang.reflect.Constructor;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * The single way to read a {@link DetectionRuleSet}. Every set is built at most once and shared by
 * reference, which is what keeps the rule graph small (issue #476).
 */
public final class RuleSets {

    private RuleSets() {
        // utility
    }

    private static final ClassValue<List<? extends IDetectionRule<?>>> DEFAULTS =
            new ClassValue<>() {
                @Override
                protected List<? extends IDetectionRule<?>> computeValue(Class<?> type) {
                    return List.copyOf(instantiate(type).buildRules());
                }
            };

    @Nonnull
    @SuppressWarnings("unchecked")
    public static <T> List<IDetectionRule<T>> rulesOf(
            @Nonnull Class<? extends DetectionRuleSet<T>> type) {
        return (List<IDetectionRule<T>>) DEFAULTS.get(type);
    }

    @Nonnull
    static DetectionRuleSet<?> instantiate(@Nonnull Class<?> type) {
        try {
            Constructor<?> constructor = type.getDeclaredConstructor();
            constructor.setAccessible(true);
            return (DetectionRuleSet<?>) constructor.newInstance();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(
                    type.getName() + " must have a no-argument constructor", e);
        }
    }
}
```

`ClassValue` is used rather than a map because rule builds are recursive — `ParentRules` above asks the registry for `LeafRules` while it is itself being computed. `ClassValue` handles that; a `ConcurrentHashMap.computeIfAbsent` would throw.

- [ ] **Step 5: Run the test to verify it passes**

Run: `mvn test -pl engine -Dtest=RuleSetsTest`
Expected: PASS, 6 tests.

- [ ] **Step 6: Format and commit**

```bash
mvn spotless:apply -pl engine
git add engine/src/main/java/com/ibm/engine/rule/ engine/src/test/java/com/ibm/engine/rule/
git commit -m "feat(engine): add DetectionRuleSet bases and RuleSets registry (#478)"
```

---

### Task 2: Value equality for detection contexts

**Files:**
- Modify: `engine/src/main/java/com/ibm/engine/model/context/DetectionContext.java`
- Modify: `engine/src/main/java/com/ibm/engine/model/context/KeyContext.java`
- Modify: `engine/src/main/java/com/ibm/engine/model/context/SignatureContext.java`
- Modify: `engine/src/main/java/com/ibm/engine/model/context/ProtocolContext.java`
- Modify: `engine/src/main/java/com/ibm/engine/model/context/PRNGContext.java`
- Test: `engine/src/test/java/com/ibm/engine/model/context/DetectionContextEqualityTest.java`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `equals`/`hashCode` on the five context classes above. Task 3 keys its cache on them.

Background: the contextual cache in Task 3 keys on contexts, so two contexts built the same way must be equal. Today they are compared by identity. Nothing in the codebase compares a context with `==` or puts one in a hash structure, so this is safe to add.

- [ ] **Step 1: Write the failing test**

Create `engine/src/test/java/com/ibm/engine/model/context/DetectionContextEqualityTest.java`:

```java
package com.ibm.engine.model.context;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DetectionContextEqualityTest {

    @Test
    void sameClassAndSamePropertiesAreEqual() {
        DigestContext one = new DigestContext(Map.of("kind", "MGF1"));
        DigestContext two = new DigestContext(Map.of("kind", "MGF1"));
        assertThat(one).isEqualTo(two).hasSameHashCodeAs(two);
    }

    @Test
    void differentPropertiesAreNotEqual() {
        assertThat(new DigestContext(Map.of("kind", "MGF1")))
                .isNotEqualTo(new DigestContext(Map.of("kind", "SHA")));
    }

    @Test
    void differentClassesWithTheSamePropertiesAreNotEqual() {
        assertThat(new DigestContext(Map.of("kind", "X")))
                .isNotEqualTo(new CipherContext(Map.of("kind", "X")));
    }

    @Test
    void keySubclassesAreNotEqualToEachOther() {
        assertThat(new PublicKeyContext(Map.of())).isNotEqualTo(new PrivateKeyContext(Map.of()));
    }

    @Test
    void keyContextsDifferingOnlyByKindAreNotEqual() {
        assertThat(new KeyContext(KeyContext.Kind.EC)).isNotEqualTo(new KeyContext(KeyContext.Kind.DH));
    }

    @Test
    void signatureContextsDifferingOnlyByKindAreNotEqual() {
        assertThat(new SignatureContext(SignatureContext.Kind.PSS))
                .isNotEqualTo(new SignatureContext(SignatureContext.Kind.MGF1));
    }

    @Test
    void protocolContextsCompareByKind() {
        assertThat(new ProtocolContext(ProtocolContext.Kind.TLS))
                .isEqualTo(new ProtocolContext(ProtocolContext.Kind.TLS))
                .isNotEqualTo(new ProtocolContext(ProtocolContext.Kind.NONE));
    }

    @Test
    void statelessContextsAreEqualToTheirOwnKind() {
        assertThat(new PRNGContext()).isEqualTo(new PRNGContext()).isNotEqualTo(new DigestContext());
    }

    @Test
    void mutatingTheSourceMapDoesNotChangeTheContext() {
        Map<String, String> source = new HashMap<>();
        source.put("kind", "MGF1");
        DigestContext context = new DigestContext(source);
        DigestContext reference = new DigestContext(Map.of("kind", "MGF1"));

        source.put("kind", "CHANGED");

        assertThat(context).isEqualTo(reference);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mvn test -pl engine -Dtest=DetectionContextEqualityTest`
Expected: FAIL — the first assertion already fails, because contexts compare by identity.

- [ ] **Step 3: Add equality to `DetectionContext`**

In `DetectionContext.java`, change the constructor to take a defensive copy and add the two methods. Note `Collections.unmodifiableMap(new HashMap<>(properties))` rather than `Map.copyOf`, because `Map.copyOf` rejects null keys and values and we do not control every caller's map:

```java
    protected DetectionContext(@Nonnull Map<String, String> properties) {
        this.properties = Collections.unmodifiableMap(new HashMap<>(properties));
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null || getClass() != other.getClass()) {
            return false;
        }
        return properties.equals(((DetectionContext) other).properties);
    }

    @Override
    public int hashCode() {
        return Objects.hash(getClass(), properties);
    }
```

Add imports `java.util.Collections`, `java.util.HashMap`, `java.util.Objects`.

Comparing on `getClass()` and not `instanceof` is what keeps `PublicKeyContext` and `PrivateKeyContext` apart — they add no state of their own.

- [ ] **Step 4: Add equality to the two subclasses that carry a `kind`**

In `KeyContext.java`:

```java
    @Override
    public boolean equals(Object other) {
        return super.equals(other) && kind == ((KeyContext) other).kind;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), kind);
    }
```

The cast is safe because `super.equals` already checked `getClass()`. Add the `java.util.Objects` import.

In `SignatureContext.java`, add exactly the same two methods with `SignatureContext` in the cast:

```java
    @Override
    public boolean equals(Object other) {
        return super.equals(other) && kind == ((SignatureContext) other).kind;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), kind);
    }
```

- [ ] **Step 5: Add equality to the two classes that implement the interface directly**

`ProtocolContext` and `PRNGContext` do not extend `DetectionContext`, so they need their own.

In `ProtocolContext.java`:

```java
    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null || getClass() != other.getClass()) {
            return false;
        }
        return kind == ((ProtocolContext) other).kind;
    }

    @Override
    public int hashCode() {
        return Objects.hash(getClass(), kind);
    }
```

In `PRNGContext.java` (no state at all):

```java
    @Override
    public boolean equals(Object other) {
        return other != null && getClass() == other.getClass();
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `mvn test -pl engine -Dtest=DetectionContextEqualityTest`
Expected: PASS, 9 tests.

- [ ] **Step 7: Run the whole engine and java suites**

Run: `mvn test -pl engine && mvn test -pl java`
Expected: both green. `DetectionRule` is a record holding a context, so its `equals` now compares by value — nothing in main code puts rules in a hash structure and `RuleGraphMemoizationTest` uses an `IdentityHashMap`, so nothing should move. If something does fail, stop and report it rather than working around it.

- [ ] **Step 8: Format and commit**

```bash
mvn spotless:apply -pl engine
git add engine/src/main/java/com/ibm/engine/model/context/ engine/src/test/java/com/ibm/engine/model/context/
git commit -m "feat(engine): give detection contexts value equality (#478)"
```

---

### Task 3: Contextual path in the registry

**Files:**
- Modify: `engine/src/main/java/com/ibm/engine/rule/RuleSets.java`
- Test: `engine/src/test/java/com/ibm/engine/rule/RuleSetsContextualTest.java`

**Interfaces:**
- Consumes: `DetectionRuleSet`, `ContextualDetectionRuleSet`, `RuleSets.instantiate` (Task 1); context `equals`/`hashCode` (Task 2).
- Produces: `static <T> List<IDetectionRule<T>> RuleSets.rulesOf(Class<? extends ContextualDetectionRuleSet<T>> type, IDetectionContext... contexts)`

- [ ] **Step 1: Write the failing test**

Create `engine/src/test/java/com/ibm/engine/rule/RuleSetsContextualTest.java`:

```java
package com.ibm.engine.rule;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.IDetectionContext;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

class RuleSetsContextualTest {

    static final class ContextualLeaf extends ContextualDetectionRuleSet<Object> {
        @Nonnull
        @Override
        protected List<IDetectionRule<Object>> buildRules(
                @Nonnull List<IDetectionContext> contexts) {
            return List.of();
        }
    }

    /** Builds by asking the registry for another contextual set, like BcOAEPEncoding does. */
    static final class ContextualParent extends ContextualDetectionRuleSet<Object> {
        @Nonnull
        @Override
        protected List<IDetectionRule<Object>> buildRules(
                @Nonnull List<IDetectionContext> contexts) {
            return RuleSets.rulesOf(ContextualLeaf.class, contextAt(contexts, 0));
        }
    }

    private static DigestContext mgf1() {
        return new DigestContext(Map.of("kind", "MGF1"));
    }

    @Test
    void equalContextsShareOneList() {
        assertThat(RuleSets.rulesOf(ContextualLeaf.class, mgf1()))
                .isSameAs(RuleSets.rulesOf(ContextualLeaf.class, mgf1()));
    }

    @Test
    void differentContextsGetDifferentLists() {
        assertThat(RuleSets.rulesOf(ContextualLeaf.class, mgf1()))
                .isNotSameAs(
                        RuleSets.rulesOf(
                                ContextualLeaf.class, new DigestContext(Map.of("kind", "SHA"))));
    }

    @Test
    void noContextUsesTheDefaultPath() {
        assertThat(RuleSets.rulesOf(ContextualLeaf.class))
                .isSameAs(RuleSets.rulesOf(ContextualLeaf.class));
    }

    @Test
    void aNullContextIsAllowedAndIsItsOwnKey() {
        assertThat(RuleSets.rulesOf(ContextualLeaf.class, (IDetectionContext) null))
                .isSameAs(RuleSets.rulesOf(ContextualLeaf.class, (IDetectionContext) null));
    }

    @Test
    void positionMattersWhenOneOfTwoContextsIsNull() {
        assertThat(RuleSets.rulesOf(ContextualLeaf.class, null, mgf1()))
                .isNotSameAs(RuleSets.rulesOf(ContextualLeaf.class, mgf1(), null));
    }

    @Test
    void aSetMayBuildByAskingForAnotherContextualSet() {
        assertThat(RuleSets.rulesOf(ContextualParent.class, mgf1()))
                .isSameAs(RuleSets.rulesOf(ContextualLeaf.class, mgf1()));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mvn test -pl engine -Dtest=RuleSetsContextualTest`
Expected: compilation failure — no `rulesOf(Class, IDetectionContext...)` overload.

- [ ] **Step 3: Add the contextual overload**

Add to `RuleSets.java`:

```java
    private static final ConcurrentMap<CacheKey, List<? extends IDetectionRule<?>>> CONTEXTUAL =
            new ConcurrentHashMap<>();

    private record CacheKey(Class<?> type, List<IDetectionContext> contexts) {}

    @Nonnull
    @SuppressWarnings("unchecked")
    public static <T> List<IDetectionRule<T>> rulesOf(
            @Nonnull Class<? extends ContextualDetectionRuleSet<T>> type,
            @Nonnull IDetectionContext... contexts) {
        if (contexts.length == 0) {
            return (List<IDetectionRule<T>>) DEFAULTS.get(type);
        }
        // Arrays.asList, not List.of: a context may legitimately be null, meaning "use the
        // default for that position".
        List<IDetectionContext> key = Collections.unmodifiableList(Arrays.asList(contexts.clone()));
        CacheKey cacheKey = new CacheKey(type, key);

        List<? extends IDetectionRule<?>> cached = CONTEXTUAL.get(cacheKey);
        if (cached == null) {
            // Deliberately not computeIfAbsent: builds are recursive (a set asks the registry for
            // another set while it is being built) and a nested update throws IllegalStateException.
            ContextualDetectionRuleSet<T> set = (ContextualDetectionRuleSet<T>) instantiate(type);
            cached = List.copyOf(set.buildRules(key));
            List<? extends IDetectionRule<?>> raced = CONTEXTUAL.putIfAbsent(cacheKey, cached);
            if (raced != null) {
                cached = raced;
            }
        }
        return (List<IDetectionRule<T>>) cached;
    }
```

Add imports: `com.ibm.engine.model.context.IDetectionContext`, `java.util.Arrays`, `java.util.Collections`, `java.util.concurrent.ConcurrentHashMap`, `java.util.concurrent.ConcurrentMap`.

Note on overload resolution: `rulesOf(Foo.class)` on a contextual class picks the **non-varargs** overload, because Java tries non-varargs first. That is intended — it lands on the `ClassValue` fast path and reaches `buildRules(List.of())`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `mvn test -pl engine -Dtest=RuleSetsContextualTest`
Expected: PASS, 6 tests.

- [ ] **Step 5: Run the full engine suite and commit**

```bash
mvn test -pl engine
mvn spotless:apply -pl engine
git add engine/src/main/java/com/ibm/engine/rule/RuleSets.java engine/src/test/java/com/ibm/engine/rule/RuleSetsContextualTest.java
git commit -m "feat(engine): cache the context-parameterized rule path (#478)"
```

**This completes PR 1. Open it before starting Task 4.**

---

### Task 4: Convert the nine context-parameterized Java classes

**Files:**
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/bc/digest/BcDigests.java`
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/bc/blockcipher/BcBlockCipher.java`
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/bc/blockcipher/BcBlockCipherEngine.java`
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetricblockcipher/BcAsymCipherEngine.java`
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetricblockcipher/BcOAEPEncoding.java`
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetricblockcipher/BcISO9796d1Encoding.java`
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetricblockcipher/BcPKCS1Encoding.java`
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/bc/asymmetricblockcipher/BcAsymmetricBlockCipher.java`
- Create: `java/src/main/java/com/ibm/plugin/rules/detection/bc/blockcipher/BcBlockCipherAndEngines.java`

**Interfaces:**
- Consumes: `ContextualDetectionRuleSet`, `RuleSets.rulesOf` (Tasks 1 and 3).
- Produces: nine `ContextualDetectionRuleSet<Tree>` subclasses. Each keeps a **temporary** static `rules()` shim so the rest of the module still compiles; Task 7 deletes the shims.

This task is done by hand. The scripted pass in Task 5 must not touch these nine files.

- [ ] **Step 1: Convert `BcDigests`**

`BcDigests` currently has `rules()`, `rules(IDetectionContext)` and `private static buildRules(IDetectionContext)`. Change the class declaration and replace the accessor block:

```java
public final class BcDigests extends ContextualDetectionRuleSet<Tree> {

    // ... keep infoMap, regularConstructors(...), otherConstructors(...) exactly as they are

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules(@Nonnull List<IDetectionContext> contexts) {
        IDetectionContext context = contextAt(contexts, 0);
        return Stream.concat(
                        regularConstructors(context).stream(),
                        otherConstructors(context).stream())
                .toList();
    }

    /** Temporary shim, removed in the call-site cleanup. */
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RuleSets.rulesOf(BcDigests.class);
    }

    /** Temporary shim, removed in the call-site cleanup. */
    @Nonnull
    public static List<IDetectionRule<Tree>> rules(@Nullable IDetectionContext context) {
        return RuleSets.rulesOf(BcDigests.class, context);
    }
}
```

Delete the `RULES` `Supplier` field, the private constructor, the old `private static buildRules(IDetectionContext)` (its body is exactly the `Stream.concat` shown above), and the `Memoize` import.

Take care: `regularConstructors` and `otherConstructors` stay `private static` and pick their own default when the context is null — they already do this with `detectionValueContext != null ? detectionValueContext : new DigestContext(...)`. Leave that logic untouched.

- [ ] **Step 2: Convert `BcBlockCipherEngine` and `BcAsymCipherEngine`**

Both have the same shape as `BcDigests` but with a single builder method (`simpleConstructors` / `constructors`). For each:

```java
public final class BcBlockCipherEngine extends ContextualDetectionRuleSet<Tree> {

    // ... keep enginesEmptyConstructors, enginesBlockSizeConstructors, simpleConstructors(...)

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules(@Nonnull List<IDetectionContext> contexts) {
        return simpleConstructors(contextAt(contexts, 0));
    }

    /** Temporary shim, removed in the call-site cleanup. */
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RuleSets.rulesOf(BcBlockCipherEngine.class);
    }

    /** Temporary shim, removed in the call-site cleanup. */
    @Nonnull
    public static List<IDetectionRule<Tree>> rules(@Nullable IDetectionContext context) {
        return RuleSets.rulesOf(BcBlockCipherEngine.class, context);
    }
}
```

For `BcAsymCipherEngine`, the builder method is `constructors(...)` and the class name in `rulesOf` is `BcAsymCipherEngine.class`. Everything else is identical.

- [ ] **Step 3: Convert the four two-context encoding classes**

`BcOAEPEncoding`, `BcISO9796d1Encoding`, `BcPKCS1Encoding` and `BcAsymmetricBlockCipher` each take `(encodingDetectionValueContext, engineDetectionValueContext)`. Position 0 is the encoding context, position 1 is the engine context. For each:

```java
public final class BcOAEPEncoding extends ContextualDetectionRuleSet<Tree> {

    // ... keep constructors(encodingContext, engineContext) as it is

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules(@Nonnull List<IDetectionContext> contexts) {
        return constructors(contextAt(contexts, 0), contextAt(contexts, 1));
    }

    /** Temporary shim, removed in the call-site cleanup. */
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RuleSets.rulesOf(BcOAEPEncoding.class);
    }

    /** Temporary shim, removed in the call-site cleanup. */
    @Nonnull
    public static List<IDetectionRule<Tree>> rules(
            @Nullable IDetectionContext encodingContext,
            @Nullable IDetectionContext engineContext) {
        return RuleSets.rulesOf(BcOAEPEncoding.class, encodingContext, engineContext);
    }
}
```

Replace the class name in the three places for each of the four classes. `BcAsymmetricBlockCipher`'s builder method is `buildRules(encodingContext, engineContext)` — rename it to `constructors(...)` first so it does not clash with the override, then call it from the override.

- [ ] **Step 4: Convert `BcBlockCipher` and split out `BcBlockCipherAndEngines`**

`BcBlockCipher` holds two rule lists today: `rules()`/`rules(ctx)` and `all()`/`all(ctx)`. The registry gives one list per class, so `all` moves out.

`BcBlockCipher` keeps only its own rules:

```java
public final class BcBlockCipher extends ContextualDetectionRuleSet<Tree> {

    // ... keep blockCiphers, simpleConstructors(...), specialConstructors(...)

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules(@Nonnull List<IDetectionContext> contexts) {
        IDetectionContext context = contextAt(contexts, 0);
        return Stream.of(
                        simpleConstructors(context).stream(),
                        specialConstructors(context).stream())
                .flatMap(i -> i)
                .toList();
    }

    /** Temporary shim, removed in the call-site cleanup. */
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RuleSets.rulesOf(BcBlockCipher.class);
    }

    /** Temporary shim, removed in the call-site cleanup. */
    @Nonnull
    public static List<IDetectionRule<Tree>> rules(@Nullable IDetectionContext context) {
        return RuleSets.rulesOf(BcBlockCipher.class, context);
    }

    /** Temporary shim, removed in the call-site cleanup. */
    @Nonnull
    public static List<IDetectionRule<Tree>> all() {
        return RuleSets.rulesOf(BcBlockCipherAndEngines.class);
    }

    /** Temporary shim, removed in the call-site cleanup. */
    @Nonnull
    public static List<IDetectionRule<Tree>> all(@Nullable IDetectionContext context) {
        return RuleSets.rulesOf(BcBlockCipherAndEngines.class, context);
    }
}
```

Create `java/src/main/java/com/ibm/plugin/rules/detection/bc/blockcipher/BcBlockCipherAndEngines.java`:

```java
package com.ibm.plugin.rules.detection.bc.blockcipher;

import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.ContextualDetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

/** All block-cipher rules, including every engine. Was {@code BcBlockCipher.all()}. */
public final class BcBlockCipherAndEngines extends ContextualDetectionRuleSet<Tree> {

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules(@Nonnull List<IDetectionContext> contexts) {
        IDetectionContext context = contextAt(contexts, 0);
        return Stream.of(
                        RuleSets.rulesOf(BcBlockCipher.class, context).stream(),
                        RuleSets.rulesOf(BcBlockCipherEngine.class, context).stream())
                .flatMap(i -> i)
                .toList();
    }
}
```

- [ ] **Step 5: Compile and run the java suite**

Run: `mvn test -pl java`
Expected: green, except the known `SecureRandomGetInstanceTest` baseline failure. The old `RuleMemoizationEnforcementTest` must still pass: the shims delegate to the registry, so `rules()` still returns one identity.

- [ ] **Step 6: Check the graph size did not grow**

Run: `mvn test -pl java -Dtest=RuleGraphMemoizationTest`
Expected: PASS. The printed `[#476] distinct reachable rule objects` should be at or below 2,563. It may drop, because the five call sites that pass an identical MGF1 `DigestContext` now share one subtree.

- [ ] **Step 7: Format and commit**

```bash
mvn spotless:apply -pl java
git add java/src/main/java/com/ibm/plugin/rules/detection/bc/
git commit -m "refactor(java): convert context-parameterized rule sets to the registry (#478)"
```

---

### Task 5: Convert the remaining Java rule classes

**Files:**
- Modify: the other ~126 classes under `java/src/main/java/com/ibm/plugin/rules/detection/`
- Create: `/tmp/convert_rule_sets.py` (throwaway, do not commit)

**Interfaces:**
- Consumes: `DetectionRuleSet`, `RuleSets.rulesOf` (Task 1).
- Produces: every remaining Java rule class extends `DetectionRuleSet<Tree>` with a `protected buildRules()` override, each keeping a temporary static `rules()` shim.

There are two shapes to handle, from the actual counts in the module: 51 classes use `Memoize.of(ClassName::buildRules)` and already have a `private static buildRules()`; the rest use `Memoize.of(() -> <expression>)`.

- [ ] **Step 1: Write the conversion script**

Create `/tmp/convert_rule_sets.py`:

```python
import os, re, sys

ROOT = sys.argv[1]                    # e.g. java/src/main/java/com/ibm/plugin/rules/detection
SKIP = set(sys.argv[2:])              # class names converted by hand

# The regexes below hardcode the simple name `Tree`, which is what java, python and go all use.
# The csharp module uses CSharpTree and is converted by hand in Task 10.

converted, skipped, manual = [], [], []

for dirpath, _, names in os.walk(ROOT):
    for name in names:
        if not name.endswith(".java"):
            continue
        cls = name[:-5]
        path = os.path.join(dirpath, name)
        src = open(path).read()
        if cls in SKIP or "Memoize.of(" not in src:
            skipped.append(cls)
            continue

        memo = re.search(
            r"[ \t]*private static final Supplier<List<IDetectionRule<Tree>>> RULES =\s*"
            r"Memoize\.of\((.*?)\);\n",
            src, re.S)
        accessor = re.search(
            r"[ \t]*@Nonnull\n[ \t]*public static List<IDetectionRule<Tree>> rules\(\) \{\n"
            r"[ \t]*return RULES\.get\(\);\n[ \t]*\}\n",
            src)
        if not memo or not accessor:
            manual.append(cls)
            continue

        expr = " ".join(memo.group(1).split())
        src = src.replace(memo.group(0), "")

        if expr == f"{cls}::buildRules":
            # the existing private static buildRules() becomes the override
            src = re.sub(
                r"[ \t]*@Nonnull\n([ \t]*)private static (List<IDetectionRule<Tree>> buildRules\(\))",
                r"    @Nonnull\n    @Override\n\1protected \2",
                src, count=1)
            body = None
        elif expr.startswith("() ->"):
            body = expr[len("() ->"):].strip()
        else:
            manual.append(cls)
            continue

        shim = (f"    /** Temporary shim, removed in the call-site cleanup. */\n"
                f"    @Nonnull\n"
                f"    public static List<IDetectionRule<Tree>> rules() {{\n"
                f"        return RuleSets.rulesOf({cls}.class);\n"
                f"    }}\n")
        if body is not None:
            shim += (f"\n    @Nonnull\n    @Override\n"
                     f"    protected List<IDetectionRule<Tree>> buildRules() {{\n"
                     f"        return {body};\n    }}\n")
        src = src.replace(accessor.group(0), shim)

        # extend the base, drop the now-pointless private constructor
        src = src.replace(f"public final class {cls} {{",
                          f"public final class {cls} extends DetectionRuleSet<Tree> {{}}"[:-1], 1)
        src = re.sub(rf"[ \t]*private {cls}\(\) \{{\n(?:[^\n]*\n)*?[ \t]*\}}\n\n?", "", src, count=1)

        src = src.replace("import com.ibm.plugin.rules.detection.Memoize;\n", "")
        src = re.sub(r"import java\.util\.function\.Supplier;\n", "", src)
        src = src.replace(
            "import com.ibm.engine.rule.IDetectionRule;\n",
            "import com.ibm.engine.rule.DetectionRuleSet;\n"
            "import com.ibm.engine.rule.IDetectionRule;\n"
            "import com.ibm.engine.rule.RuleSets;\n")

        open(path, "w").write(src)
        converted.append(cls)

print(f"converted={len(converted)} untouched={len(skipped)}")
print("NEEDS MANUAL WORK:", ", ".join(sorted(manual)) or "none")
```

- [ ] **Step 2: Run the script**

```bash
python3 /tmp/convert_rule_sets.py \
  java/src/main/java/com/ibm/plugin/rules/detection \
  BcDigests BcBlockCipher BcBlockCipherEngine BcBlockCipherAndEngines BcAsymCipherEngine \
  BcOAEPEncoding BcISO9796d1Encoding BcPKCS1Encoding BcAsymmetricBlockCipher
```

Write down the list printed after `NEEDS MANUAL WORK:` — those files were not touched and you convert them by hand in the next step.

- [ ] **Step 3: Convert the leftovers by hand, then compile**

For each class the script listed, apply the same shape by hand:

```java
public final class SomeRules extends DetectionRuleSet<Tree> {

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        return List.of(CONSTRUCTOR_1, CONSTRUCTOR_2);   // whatever the Memoize lambda returned
    }

    /** Temporary shim, removed in the call-site cleanup. */
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RuleSets.rulesOf(SomeRules.class);
    }
}
```

Then let the compiler find everything the script got wrong:

```bash
mvn spotless:apply -pl java
mvn -q compile -pl java
```

Repeat fix-and-compile until it is clean. Common failures and their fix:
- *"cannot find symbol: Supplier"* — an unused import survived; delete it.
- *"buildRules() in X cannot override ... static methods cannot be overridden"* — the old method kept its `static`; remove `static` and add `@Override`.
- *"method does not override"* — the signature drifted; it must be exactly `protected List<IDetectionRule<Tree>> buildRules()`.

- [ ] **Step 4: Run the java suite**

Run: `mvn test -pl java`
Expected: green apart from the known `SecureRandomGetInstanceTest` baseline. `RuleMemoizationEnforcementTest` still passes because every shim goes through the registry.

- [ ] **Step 5: Confirm no class was missed**

```bash
grep -rl "Memoize" java/src/main/java | grep -v "detection/Memoize.java"
```

Expected: no output. If a file is listed, convert it and re-run the suite.

- [ ] **Step 6: Commit**

```bash
mvn spotless:apply -pl java
git add java/src/main/java/com/ibm/plugin/rules/detection/
git commit -m "refactor(java): convert remaining rule sets to the registry (#478)"
```

---

### Task 6: Move Java call sites to `rulesOf`

**Files:**
- Modify: all files under `java/src/main/java/` and `java/src/test/java/` that call a rule accessor (443 call sites)
- Create: `/tmp/rewrite_call_sites.py` (throwaway, do not commit)

**Interfaces:**
- Consumes: the shims from Tasks 4 and 5.
- Produces: no caller outside `com.ibm.engine.rule` reads rules any way other than `RuleSets.rulesOf(...)`.

- [ ] **Step 1: Write the rewrite script**

Create `/tmp/rewrite_call_sites.py`:

```python
import os, re, sys

RULE_ROOT = sys.argv[1]     # .../rules/detection
SCAN = sys.argv[2:]         # source roots to rewrite

names = {f[:-5] for _, _, fs in os.walk(RULE_ROOT) for f in fs if f.endswith(".java")}
names.discard("Memoize")
alt = "|".join(sorted(names, key=len, reverse=True))

# X.rules()  /  X.all()   -> RuleSets.rulesOf(X.class)
no_arg = re.compile(rf"\b({alt})\.(?:rules|all)\(\)")
# X.rules(a) / X.all(a) / X.rules(a, b) -> RuleSets.rulesOf(X.class, a, b)
with_arg = re.compile(rf"\b({alt})\.(?:rules|all)\((?![)\s])")

changed = 0
for root in SCAN:
    for dirpath, _, fs in os.walk(root):
        for f in fs:
            if not f.endswith(".java"):
                continue
            p = os.path.join(dirpath, f)
            src = open(p).read()
            new = no_arg.sub(lambda m: f"RuleSets.rulesOf({m.group(1)}.class)", src)
            new = with_arg.sub(lambda m: f"RuleSets.rulesOf({m.group(1)}.class, ", new)
            if new != src:
                if "import com.ibm.engine.rule.RuleSets;" not in new:
                    new = new.replace("\nimport ", "\nimport com.ibm.engine.rule.RuleSets;\nimport ", 1)
                open(p, "w").write(new)
                changed += 1
print("files changed:", changed)
```

Two things this deliberately does not handle, because there are only a handful and a wrong regex is worse than a manual edit:
- `BcBlockCipher.all(...)` must become `RuleSets.rulesOf(BcBlockCipherAndEngines.class, ...)`, not `BcBlockCipher`.
- `ReorganizerRules.rules()` calls return `List<IReorganizerRule>` and must not be touched.

- [ ] **Step 2: Guard the two exceptions before running**

```bash
# all() belongs to the new class
grep -rl "BcBlockCipher\.all(" java/src | xargs sed -i '' 's/BcBlockCipher\.all(/BcBlockCipherAndEngines.all(/g'
```

The script's name set includes `BcBlockCipherAndEngines`, so those become `RuleSets.rulesOf(BcBlockCipherAndEngines.class, ...)`. Add the import where the compiler asks for it in step 4.

`ReorganizerRules` classes live outside `rules/detection`, so they are not in the name set and the script cannot touch them.

- [ ] **Step 3: Run the rewrite**

```bash
python3 /tmp/rewrite_call_sites.py \
  java/src/main/java/com/ibm/plugin/rules/detection \
  java/src/main/java java/src/test/java
```

- [ ] **Step 4: Compile and fix**

```bash
mvn spotless:apply -pl java
mvn -q compile -pl java
mvn -q test-compile -pl java
```

Fix what the compiler reports — mostly missing `BcBlockCipherAndEngines` imports. Repeat until clean.

- [ ] **Step 5: Verify no old-style call remains**

```bash
grep -rnE "\b[A-Z][A-Za-z0-9_]*\.(rules|all)\(" java/src --include=*.java | grep -v Reorganizer
```

Expected: no output.

- [ ] **Step 6: Run the java suite and the footprint test**

```bash
mvn test -pl java
mvn test -pl java -Dtest=RuleGraphMemoizationTest
```

Expected: green apart from the known baseline; distinct rule objects at or below 2,563.

- [ ] **Step 7: Commit**

```bash
mvn spotless:apply -pl java
git add java/src
git commit -m "refactor(java): read detection rules through RuleSets (#478)"
```

---

### Task 7: Delete the Java shims and add the guard test

**Files:**
- Modify: the Java rule classes that still carry a `rules()` shim
- Delete: `java/src/main/java/com/ibm/plugin/rules/detection/Memoize.java`
- Delete: `java/src/test/java/com/ibm/plugin/rules/detection/MemoizeTest.java`
- Delete: `java/src/test/java/com/ibm/plugin/rules/RuleMemoizationEnforcementTest.java`
- Create: `java/src/test/java/com/ibm/plugin/rules/RuleAccessorEnforcementTest.java`

**Interfaces:**
- Consumes: everything from Tasks 4 to 6.
- Produces: a build-failing check that no rule class exposes a static rule accessor. Tasks 8, 9 and 10 copy this test file into their module, changing only the package-scan constant if needed.

- [ ] **Step 1: Write the new guard test**

Create `java/src/test/java/com/ibm/plugin/rules/RuleAccessorEnforcementTest.java`:

```java
package com.ibm.plugin.rules;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import java.io.File;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Rules are read through {@code RuleSets.rulesOf(...)}, which builds each set once and shares it
 * (issue #476). A static accessor on a rule class would be a second door that can rebuild a shared
 * subtree, so there must not be one. The compiler cannot police a static method — this test does.
 */
class RuleAccessorEnforcementTest {

    private static final String RULE_PACKAGE = "com.ibm.plugin.rules.detection";

    /** Guards against the scan silently matching nothing (e.g. a package rename). */
    private static final int MIN_EXPECTED_RULE_SETS = 10;

    @Test
    void noRuleClassExposesAStaticRuleAccessor() throws Exception {
        List<String> violations = new ArrayList<>();
        int ruleSets = 0;

        for (String className : discoverClassNames()) {
            Class<?> clazz = Class.forName(className, false, getClass().getClassLoader());
            if (DetectionRuleSet.class.isAssignableFrom(clazz)
                    && !Modifier.isAbstract(clazz.getModifiers())) {
                ruleSets++;
            }
            for (Method method : clazz.getDeclaredMethods()) {
                if (Modifier.isStatic(method.getModifiers())
                        && Modifier.isPublic(method.getModifiers())
                        && returnsRuleList(method)) {
                    violations.add(clazz.getName() + "#" + method.getName());
                }
            }
        }

        assertThat(ruleSets)
                .as("rule sets discovered under %s", RULE_PACKAGE)
                .isGreaterThanOrEqualTo(MIN_EXPECTED_RULE_SETS);
        assertThat(violations)
                .as(
                        "static rule accessors — extend DetectionRuleSet and let callers use"
                                + " RuleSets.rulesOf(...) instead (see #476, #478)")
                .isEmpty();
    }

    private static boolean returnsRuleList(Method method) {
        if (!List.class.isAssignableFrom(method.getReturnType())) {
            return false;
        }
        Type returnType = method.getGenericReturnType();
        return returnType instanceof ParameterizedType list
                && list.getActualTypeArguments()[0] instanceof ParameterizedType element
                && element.getRawType().equals(IDetectionRule.class);
    }

    private Set<String> discoverClassNames() throws Exception {
        Set<String> names = new LinkedHashSet<>();
        Enumeration<URL> roots =
                getClass().getClassLoader().getResources(RULE_PACKAGE.replace('.', '/'));
        while (roots.hasMoreElements()) {
            Path base = Path.of(roots.nextElement().toURI());
            try (Stream<Path> paths = Files.walk(base)) {
                paths.filter(p -> p.toString().endsWith(".class"))
                        .filter(p -> !p.getFileName().toString().contains("$"))
                        .forEach(
                                p -> {
                                    String relative =
                                            base.relativize(p)
                                                    .toString()
                                                    .replace(File.separatorChar, '.');
                                    names.add(
                                            RULE_PACKAGE
                                                    + "."
                                                    + relative.substring(
                                                            0,
                                                            relative.length() - ".class".length()));
                                });
            }
        }
        return names;
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `mvn test -pl java -Dtest=RuleAccessorEnforcementTest`
Expected: FAIL, listing every remaining `rules()` / `all()` shim.

- [ ] **Step 3: Delete the shims**

```bash
python3 - <<'PY'
import os, re
root = "java/src/main/java/com/ibm/plugin/rules/detection"
pat = re.compile(
    r"[ \t]*/\*\* Temporary shim, removed in the call-site cleanup\. \*/\n"
    r"[ \t]*@Nonnull\n"
    r"[ \t]*public static List<IDetectionRule<Tree>> (?:rules|all)\([^)]*\) \{\n"
    r"(?:[^\n]*\n)*?[ \t]*\}\n\n?", re.M)
for dirpath, _, fs in os.walk(root):
    for f in fs:
        if f.endswith(".java"):
            p = os.path.join(dirpath, f)
            src = open(p).read()
            new = pat.sub("", src)
            if new != src:
                open(p, "w").write(new)
print("shims removed")
PY
mvn spotless:apply -pl java
mvn -q test-compile -pl java
```

Fix any compile error the same way as before. A leftover `@Nullable` or `IDetectionContext` import that is now unused will trip Checkstyle — delete it.

- [ ] **Step 4: Delete `Memoize` and the old enforcement test**

```bash
git rm java/src/main/java/com/ibm/plugin/rules/detection/Memoize.java \
       java/src/test/java/com/ibm/plugin/rules/detection/MemoizeTest.java \
       java/src/test/java/com/ibm/plugin/rules/RuleMemoizationEnforcementTest.java
```

- [ ] **Step 5: Run the guard test and the full suite**

```bash
mvn test -pl java -Dtest=RuleAccessorEnforcementTest
mvn test -pl java
```

Expected: guard test PASS; suite green apart from the known `SecureRandomGetInstanceTest` baseline.

- [ ] **Step 6: Commit**

```bash
mvn spotless:apply -pl java
git add -A java/src
git commit -m "refactor(java): drop Memoize and enforce registry-only rule access (#478)"
```

**This completes PR 2. Open it before starting Task 8.**

---

### Task 8: Convert the Python module

**Files:**
- Modify: 22 rule classes under `python/src/main/java/com/ibm/plugin/rules/detection/`
- Modify: `python/src/main/java/com/ibm/plugin/rules/PythonInventoryRule.java`
- Modify: `python/src/test/java/com/ibm/plugin/TestBase.java`, `python/src/test/java/com/ibm/plugin/ExportPythonRulesToJsonTest.java`
- Delete: `python/src/main/java/com/ibm/plugin/rules/detection/Memoize.java`
- Delete: `python/src/test/java/com/ibm/plugin/rules/RuleMemoizationEnforcementTest.java`
- Create: `python/src/test/java/com/ibm/plugin/rules/RuleAccessorEnforcementTest.java`

**Interfaces:**
- Consumes: `DetectionRuleSet`, `RuleSets.rulesOf` (Task 1); the guard test written in Task 7.
- Produces: nothing later tasks depend on.

Python is smaller and uniform — every class uses `Memoize.of(ClassName::buildRules)` and none takes a context, so this is one pass rather than three. The tree type is `org.sonar.plugins.python.api.tree.Tree`.

- [ ] **Step 1: Convert the classes**

```bash
python3 /tmp/convert_rule_sets.py \
  python/src/main/java/com/ibm/plugin/rules/detection
```

Convert anything printed after `NEEDS MANUAL WORK:` by hand, using the shape from Task 5 step 3.

- [ ] **Step 2: Rewrite the call sites**

```bash
python3 /tmp/rewrite_call_sites.py \
  python/src/main/java/com/ibm/plugin/rules/detection \
  python/src/main/java python/src/test/java
```

- [ ] **Step 3: Delete the shims, `Memoize` and the old test**

Run the shim-removal snippet from Task 7 step 3 with `root = "python/src/main/java/com/ibm/plugin/rules/detection"`, then:

```bash
git rm python/src/main/java/com/ibm/plugin/rules/detection/Memoize.java \
       python/src/test/java/com/ibm/plugin/rules/RuleMemoizationEnforcementTest.java
```

- [ ] **Step 4: Add the guard test**

Copy `java/src/test/java/com/ibm/plugin/rules/RuleAccessorEnforcementTest.java` to
`python/src/test/java/com/ibm/plugin/rules/RuleAccessorEnforcementTest.java` unchanged — the package and the scanned rule package are the same in every module.

- [ ] **Step 5: Compile, test, verify**

```bash
mvn spotless:apply -pl python
mvn test -pl python
grep -rn "Memoize" python/src ; grep -rnE "\b[A-Z][A-Za-z0-9_]*\.rules\(" python/src --include=*.java | grep -v Reorganizer
```

Expected: suite green; both greps produce no output.

- [ ] **Step 6: Commit**

```bash
git add -A python/src
git commit -m "refactor(python): read detection rules through RuleSets (#478)"
```

**This completes PR 3.**

---

### Task 9: Convert the Go module

**Files:**
- Modify: 23 rule classes under `go/src/main/java/com/ibm/plugin/rules/detection/`
- Modify: `go/src/main/java/com/ibm/plugin/rules/GoInventoryRule.java`, `go/src/test/java/com/ibm/plugin/TestBase.java`
- Delete: `go/src/main/java/com/ibm/plugin/rules/detection/Memoize.java`
- Delete: `go/src/test/java/com/ibm/plugin/rules/RuleMemoizationEnforcementTest.java`
- Create: `go/src/test/java/com/ibm/plugin/rules/RuleAccessorEnforcementTest.java`

**Interfaces:**
- Consumes: `DetectionRuleSet`, `RuleSets.rulesOf` (Task 1); the guard test from Task 7.
- Produces: nothing later tasks depend on.

Go has 44 main and 34 test call sites. Every class uses `Memoize.of(ClassName::buildRules)`, none takes a context, and there is no `all()` rule accessor — the only `.all(` in the module is `checks.all()` on the SonarQube Checks API, which must not be touched. So this is one pass, like Python. The tree type is `org.sonar.plugins.go.api.Tree`.

- [ ] **Step 1: Convert the classes**

```bash
python3 /tmp/convert_rule_sets.py \
  go/src/main/java/com/ibm/plugin/rules/detection
```

Convert anything printed after `NEEDS MANUAL WORK:` by hand, using the shape from Task 5 step 3.

- [ ] **Step 2: Rewrite the call sites**

```bash
python3 /tmp/rewrite_call_sites.py \
  go/src/main/java/com/ibm/plugin/rules/detection \
  go/src/main/java go/src/test/java
```

- [ ] **Step 3: Delete the shims, `Memoize` and the old test**

Run the shim-removal snippet from Task 7 step 3 with `root = "go/src/main/java/com/ibm/plugin/rules/detection"`, then:

```bash
git rm go/src/main/java/com/ibm/plugin/rules/detection/Memoize.java \
       go/src/test/java/com/ibm/plugin/rules/RuleMemoizationEnforcementTest.java
```

- [ ] **Step 4: Add the guard test**

Copy `java/src/test/java/com/ibm/plugin/rules/RuleAccessorEnforcementTest.java` to `go/src/test/java/com/ibm/plugin/rules/RuleAccessorEnforcementTest.java` unchanged.

- [ ] **Step 5: Compile, test, verify**

```bash
mvn spotless:apply -pl go
mvn test -pl go
grep -rn "Memoize" go/src ; grep -rnE "\b[A-Z][A-Za-z0-9_]*\.(rules|all)\(" go/src --include=*.java | grep -v Reorganizer
```

Expected: suite green; both greps produce no output.

- [ ] **Step 6: Commit**

```bash
git add -A go/src
git commit -m "refactor(go): read detection rules through RuleSets (#478)"
```

**This completes PR 4.**

---

### Task 10: Convert the C# module

**Files:**
- Modify: 12 rule classes under `csharp/src/main/java/com/ibm/plugin/rules/detection/`
- Modify: `csharp/src/main/java/com/ibm/plugin/rules/CSharpInventoryRule.java`, `csharp/src/main/java/com/ibm/plugin/rules/detection/CSharpBaseDetectionRule.java`, `csharp/src/test/java/com/ibm/plugin/TestBase.java`
- Create: `csharp/src/test/java/com/ibm/plugin/rules/RuleAccessorEnforcementTest.java`

**Interfaces:**
- Consumes: `DetectionRuleSet`, `RuleSets.rulesOf` (Task 1); the guard test from Task 7.
- Produces: nothing later tasks depend on.

C# never had `Memoize` at all — its rule classes rebuild on every call today. It has no `Memoize.java` to delete and no old enforcement test to remove. The tree type is `com.ibm.engine.language.csharp.tree.CSharpTree`. `CSharpBaseDetectionRule` calls `CSharpDetectionRules.rules()` in its constructor and must be updated too.

- [ ] **Step 1: Convert the classes by hand**

There are only 12 and the script keys on `Memoize.of(`, which is absent here, so convert each by hand. For every class under `csharp/src/main/java/com/ibm/plugin/rules/detection/`:

```java
public final class DotNetAES extends DetectionRuleSet<CSharpTree> {

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(/* exactly what the old rules() returned */);
    }
}
```

Delete the private constructor and the old `public static rules()`. Add `import com.ibm.engine.rule.DetectionRuleSet;`.

`CSharpDetectionRules` converts the same way; its `buildRules()` body becomes the `Stream.of(...)` block with each `DotNetX.rules().stream()` replaced by `RuleSets.rulesOf(DotNetX.class).stream()`.

Do **not** touch `CSharpBaseDetectionRule` — it is an abstract check class, not a rule set.

- [ ] **Step 2: Update the three external call sites**

In `CSharpBaseDetectionRule.java`, `CSharpInventoryRule.java` and `csharp/src/test/java/com/ibm/plugin/TestBase.java`, replace `CSharpDetectionRules.rules()` with `RuleSets.rulesOf(CSharpDetectionRules.class)` and add `import com.ibm.engine.rule.RuleSets;`.

- [ ] **Step 3: Add the guard test**

Copy `java/src/test/java/com/ibm/plugin/rules/RuleAccessorEnforcementTest.java` to `csharp/src/test/java/com/ibm/plugin/rules/RuleAccessorEnforcementTest.java`, and lower `MIN_EXPECTED_RULE_SETS` from 10 to 5 — this module has 13 rule classes but the constant only needs to prove the scan found something.

- [ ] **Step 4: Compile, test, verify**

```bash
mvn spotless:apply -pl csharp
mvn test -pl csharp
grep -rnE "\b[A-Z][A-Za-z0-9_]*\.rules\(" csharp/src --include=*.java | grep -v Reorganizer
```

Expected: suite green; the grep produces no output.

- [ ] **Step 5: Commit**

```bash
git add -A csharp/src
git commit -m "refactor(csharp): read detection rules through RuleSets (#478)"
```

**This completes PR 5.**

---

### Task 11: Whole-repository verification

**Files:** none changed unless a check fails.

**Interfaces:**
- Consumes: everything above.
- Produces: the evidence the spec's acceptance criteria ask for.

- [ ] **Step 1: Full build**

Run: `mvn clean package`
Expected: BUILD SUCCESS. Only the known `SecureRandomGetInstanceTest` baseline may fail. If `JsonCipherSuites.java` was truncated by the build, restore it with `git checkout -- <path>` and rerun.

- [ ] **Step 2: Confirm `Memoize` is gone from the whole repository**

```bash
grep -rn "Memoize" --include=*.java . | grep -v target
```

Expected: no output.

- [ ] **Step 3: Confirm the guard test runs in all four modules**

```bash
for m in java python go csharp; do
  echo "--- $m"; mvn -q test -pl $m -Dtest=RuleAccessorEnforcementTest
done
```

Expected: four passes.

- [ ] **Step 4: Record the rule-graph footprint**

```bash
mvn test -pl java -Dtest=RuleGraphMemoizationTest | grep "distinct reachable rule objects"
```

Expected: a number at or below 2,563. Put the number in the PR description — the spec predicts a small drop, because the five call sites that pass an identical MGF1 `DigestContext` now share one subtree.

- [ ] **Step 5: Confirm the CBOM output is unchanged**

```bash
mvn test -pl java -Dtest=ExportJavaRulesToJsonTest
git status --short
```

Expected: the test passes and produces no unexpected working-tree changes. If a generated JSON does change, stop and compare it against `main` before going further — the rules themselves must be identical, only their sharing changed.

- [ ] **Step 6: Commit anything the verification fixed**

```bash
git status --short
# only if something needed fixing:
git add -A && git commit -m "fix: address verification findings (#478)"
```

---

## Notes for the reviewer

- The three Java passes (Tasks 4-7) exist so the module compiles and its tests run at every commit. The temporary `rules()` shims are what make that possible; Task 7 removes the last of them, and the guard test proves none survived.
- Tasks 5, 6 and 8-10 use throwaway scripts under `/tmp`. Do not commit them. The compiler and the guard test are the real safety net — the scripts only save typing.
- The one behavioural change in this plan is Task 2: contexts gain value equality and `DetectionContext` copies its property map. Everything else is a move of the same objects behind a different door.
