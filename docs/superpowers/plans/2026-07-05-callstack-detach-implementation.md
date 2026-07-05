# Call-stack AST-Detach Heap Reduction — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the per-language `CallStackAgent` from pinning whole-file ASTs across a scan by storing tree-free "detached" records for eligible Java method calls, cutting the measured ~7 GB / ~179k-`CallContext` runtime heap without regressing cross-file detection.

**Architecture:** `CallContext` becomes a sealed interface with two variants: `RetainedCall` (today's `tree + scanContext`, unchanged behavior) and `DetachedCall` (match keys + per-argument pre-resolved value snapshots + an AST-free `DetachedScanContext`). At record time the Java engine pre-resolves each argument while the file is live and, if faithfully reproducible, stores a `DetachedCall`; otherwise it keeps a `RetainedCall`. At hook-fire time a detached record replays from its snapshot, producing detection values whose location is a synthetic AST-free `DetachedSyntaxToken`. Because a `DetachedCall` holds no `Tree` and no `JavaFileScannerContext`, the file's AST becomes GC-eligible after `leaveFile`.

**Tech Stack:** Java 17, Maven multi-module, sonar-java 8.0.1 `CheckVerifier`, JUnit 5 + AssertJ.

## Global Constraints

- Java 17; changes live in `engine` (+ Java language support) and `java` (translator + tests). Do not modify Python/Go behavior.
- Apache 2.0 license header in every new `.java` file — copy the 19-line header verbatim from any neighbor (e.g. `engine/src/main/java/com/ibm/engine/callstack/CallContext.java:1-19`).
- Run `mvn spotless:apply` before every commit. If Spotless truncates `mapper/.../JsonCipherSuites.java`, restore it (`git checkout -- <path>`) before committing.
- `mvn test -pl engine` and `mvn test -pl java` must stay green after every task.
- Keep the generic engine language-agnostic: the detachability decision and pre-resolution live in the Java layer; the generic `CallStackAgent` only stores/keys/replays `CallContext` variants.
- **Scope for this iteration:** only Java **method invocations** are detachable. Enum accesses (`Tree.Kind.ENUM`), Python, and Go always use `RetainedCall` (unchanged).

---

## File Structure

- `engine/.../callstack/CallContext.java` — MODIFY → `sealed interface CallContext<R,T> permits RetainedCall, DetachedCall`.
- `engine/.../callstack/RetainedCall.java` — CREATE — record `(T tree, IScanContext scanContext)`; today's shape.
- `engine/.../callstack/DetachedCall.java` — CREATE — record with match keys, `List<ArgSnapshot>`, `DetachedScanContext`.
- `engine/.../callstack/ArgSnapshot.java` — CREATE — one argument's resolved raw values + location primitives.
- `engine/.../callstack/DetachedSyntaxToken.java` — CREATE — AST-free `SyntaxToken` for value locations.
- `engine/.../callstack/DetachedScanContext.java` — CREATE — AST-free `IScanContext` (InputFile + filePath).
- `engine/.../callstack/CallStackAgent.java` — MODIFY — variant-aware add/key/match; drop `visitedTreeObjects`; key-indexed lookup.
- `engine/.../detection/MethodMatcher.java` — MODIFY — add `matchKeys(...)` overload.
- `engine/.../detection/DetectionStoreWithHook.java` — MODIFY — detached replay branch.
- `engine/.../hooks/{HookRepository,IHook,EnumHook,MethodInvocationHookWithParameterResolvement,MethodInvocationHookWithReturnResolvement,HookDetectionObservable,IHookDetectionObserver}.java` — MODIFY — consume sealed `CallContext` / carry the record through fire.
- `engine/.../detection/DetectionStore.java` — MODIFY — `onHookInvocation` carries the `CallContext`.
- `engine/.../language/ILanguageSupport.java` — MODIFY — `isDetachableCall` default `false`.
- `engine/.../language/java/JavaLanguageSupport.java` — MODIFY — Java `isDetachableCall`.
- `engine/.../language/java/JavaDetectionEngine.java` — MODIFY — record-time pre-resolution + build variant; expose a location-primitive capture helper.
- `java/.../plugin/translation/translator/JavaTranslator.java` — MODIFY — leading `DetachedSyntaxToken` branch in `getDetectionContextFrom`.
- `java/src/test/files/rules/detection/crossfile/CrossFileDefinition.java` + `CrossFileUsage.java` — CREATE — multi-file fixtures.
- `java/src/test/java/com/ibm/plugin/rules/detection/crossfile/CrossFileHookDetachTest.java` — CREATE — cross-file regression guard.

---

## Task 1: Characterization test — cross-file hook detection baseline

Locks current cross-file behavior BEFORE any refactor. This is the regression guard; it must pass on unmodified code and after every later task.

**Files:**
- Create: `java/src/test/files/rules/detection/crossfile/CrossFileDefinition.java`
- Create: `java/src/test/files/rules/detection/crossfile/CrossFileUsage.java`
- Create: `java/src/test/java/com/ibm/plugin/rules/detection/crossfile/CrossFileHookDetachTest.java`

**Interfaces:**
- Consumes: `TestBase` (`java/src/test/java/com/ibm/plugin/TestBase.java`), `CheckVerifier` (sonar-java).
- Produces: nothing code-facing; establishes the green baseline all later tasks preserve.

- [ ] **Step 1: Write the definition fixture** (a wrapper method whose algorithm arg is a plain `String` parameter — forces a parameter hook). NOT a test source; no license header needed (matches other `src/test/files`).

`java/src/test/files/rules/detection/crossfile/CrossFileDefinition.java`:
```java
package rules.detection.crossfile;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;

public class CrossFileDefinition {
    public Cipher make(String transformation) throws GeneralSecurityException {
        return Cipher.getInstance(transformation); // hook: resolve 'transformation' from caller
    }
}
```

- [ ] **Step 2: Write the usage fixture** (calls the wrapper with a literal — this is the call recorded in "file A"):

`java/src/test/files/rules/detection/crossfile/CrossFileUsage.java`:
```java
package rules.detection.crossfile;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;

public class CrossFileUsage {
    public Cipher use() throws GeneralSecurityException {
        return new CrossFileDefinition().make("AES/GCM/NoPadding");
    }
}
```

- [ ] **Step 3: Write the multi-file test.** Uses `CheckVerifier.newVerifier().onFiles(usage, definition)` so the usage (call site) is analyzed before the definition (hook site), exercising the `onNewHookSubscription` retro-scan across files. Assert that the resolved algorithm value `"AES"` reaches a detection value.

`java/src/test/java/com/ibm/plugin/rules/detection/crossfile/CrossFileHookDetachTest.java`:
```java
/* <Apache 2.0 header copied verbatim from TestBase.java:1-19> */
package com.ibm.plugin.rules.detection.crossfile;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class CrossFileHookDetachTest extends TestBase {

    private static boolean sawAes = false;

    @Test
    void crossFileLiteralResolves() {
        sawAes = false;
        CheckVerifier.newVerifier()
                .onFiles(
                        "src/test/files/rules/detection/crossfile/CrossFileUsage.java",
                        "src/test/files/rules/detection/crossfile/CrossFileDefinition.java")
                .withCheck(this)
                .verifyNoIssues();
        assertThat(sawAes).as("cross-file resolved algorithm value 'AES'").isTrue();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        collectValues(detectionStore);
    }

    private void collectValues(
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store) {
        for (IValue<Tree> value : store.getDetectionValues()) {
            if (value.asString().contains("AES")) {
                sawAes = true;
            }
        }
        store.getChildren().forEach(this::collectValues);
    }
}
```

- [ ] **Step 4: Run the test — verify it PASSES on unmodified code.**

Run: `mvn test -pl java -Dtest=CrossFileHookDetachTest`
Expected: PASS, `sawAes` true. (If it fails, the fixtures don't trigger a parameter hook — adjust the wrapper so the algorithm is a method parameter, not a literal inside the wrapper, and re-run. Do not proceed until green.)

- [ ] **Step 5: Commit.**
```bash
mvn spotless:apply
git add java/src/test/files/rules/detection/crossfile java/src/test/java/com/ibm/plugin/rules/detection/crossfile
git commit -m "test: cross-file hook detection characterization baseline"
```

---

## Task 2: `DetachedSyntaxToken` — AST-free value location

**Files:**
- Create: `engine/src/main/java/com/ibm/engine/callstack/DetachedSyntaxToken.java`
- Test: `engine/src/test/java/com/ibm/engine/callstack/DetachedSyntaxTokenTest.java`

**Interfaces:**
- Produces: `DetachedSyntaxToken(int line, int columnOffset, int endLine, int endColumnOffset, String text, List<String> keywords) implements SyntaxToken`, plus getter `List<String> keywords()`. `parent()` returns `null`; `kind()` returns `Tree.Kind.TOKEN`; `firstToken()`/`lastToken()` return `this`; `range()` returns `Range.at(Position.at(line, columnOffset), Position.at(endLine, endColumnOffset))`.

- [ ] **Step 1: Write the failing test.**
```java
/* <Apache header> */
package com.ibm.engine.callstack;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.java.api.tree.Tree;

class DetachedSyntaxTokenTest {
    @Test
    void pinsNothingAndReportsRange() {
        DetachedSyntaxToken t =
                new DetachedSyntaxToken(12, 4, 12, 20, "AES", List.of("javax.crypto.Cipher#getInstance"));
        assertThat(t.parent()).isNull();
        assertThat(t.kind()).isEqualTo(Tree.Kind.TOKEN);
        assertThat(t.firstToken()).isSameAs(t);
        assertThat(t.range().start().line()).isEqualTo(12);
        assertThat(t.range().start().columnOffset()).isEqualTo(4);
        assertThat(t.keywords()).containsExactly("javax.crypto.Cipher#getInstance");
        assertThat(t.text()).isEqualTo("AES");
    }
}
```

- [ ] **Step 2: Run — verify it fails to compile (class missing).**
Run: `mvn test -pl engine -Dtest=DetachedSyntaxTokenTest`
Expected: FAIL — `cannot find symbol DetachedSyntaxToken`.

- [ ] **Step 3: Implement the class.**
```java
/* <Apache header> */
package com.ibm.engine.callstack;

import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.plugins.java.api.location.Position;
import org.sonar.plugins.java.api.location.Range;
import org.sonar.plugins.java.api.tree.SyntaxToken;
import org.sonar.plugins.java.api.tree.SyntaxTrivia;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.TreeVisitor;

/** AST-free {@link SyntaxToken} used as the location of a detached cross-file detection value.
 *  Holds only primitives, so it never pins a compilation unit ({@link #parent()} is null). */
public final class DetachedSyntaxToken implements SyntaxToken {
    private final int line;
    private final int columnOffset;
    private final int endLine;
    private final int endColumnOffset;
    @Nonnull private final String text;
    @Nonnull private final List<String> keywords;

    public DetachedSyntaxToken(int line, int columnOffset, int endLine, int endColumnOffset,
            @Nonnull String text, @Nonnull List<String> keywords) {
        this.line = line;
        this.columnOffset = columnOffset;
        this.endLine = endLine;
        this.endColumnOffset = endColumnOffset;
        this.text = text;
        this.keywords = List.copyOf(keywords);
    }

    @Nonnull public List<String> keywords() { return keywords; }
    public int offset() { return columnOffset; }

    @Override public String text() { return text; }
    @Override public List<SyntaxTrivia> trivias() { return List.of(); }
    @Override public int line() { return line; }
    @Override public int column() { return columnOffset; }
    @Override public Range range() {
        return Range.at(Position.at(line, columnOffset + 1), Position.at(endLine, endColumnOffset + 1));
    }
    @Override public boolean is(Tree.Kind... kinds) {
        for (Tree.Kind k : kinds) { if (k == Tree.Kind.TOKEN) return true; }
        return false;
    }
    @Override public void accept(TreeVisitor visitor) { /* detached: no traversal */ }
    @Nullable @Override public Tree parent() { return null; }
    @Override public SyntaxToken firstToken() { return this; }
    @Override public SyntaxToken lastToken() { return this; }
    @Override public Tree.Kind kind() { return Tree.Kind.TOKEN; }

    @Override public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DetachedSyntaxToken t)) return false;
        return line == t.line && columnOffset == t.columnOffset && endLine == t.endLine
                && endColumnOffset == t.endColumnOffset && text.equals(t.text) && keywords.equals(t.keywords);
    }
    @Override public int hashCode() {
        int r = line;
        r = 31 * r + columnOffset;
        r = 31 * r + endLine;
        r = 31 * r + endColumnOffset;
        r = 31 * r + text.hashCode();
        r = 31 * r + keywords.hashCode();
        return r;
    }
}
```
Note: `Position.at` is 1-based on column in sonar-java; capture `columnOffset` 0-based and add 1 here so `range().start().columnOffset()` returns the original 0-based value. Verify against Step-1 assertion; adjust the `+1`/`-1` if the assertion fails.

- [ ] **Step 4: Run — verify PASS** (fix the column offset convention if the range assertion fails).
Run: `mvn test -pl engine -Dtest=DetachedSyntaxTokenTest`
Expected: PASS.

- [ ] **Step 5: Commit.**
```bash
mvn spotless:apply
git add engine/src/main/java/com/ibm/engine/callstack/DetachedSyntaxToken.java engine/src/test/java/com/ibm/engine/callstack/DetachedSyntaxTokenTest.java
git commit -m "feat(engine): AST-free DetachedSyntaxToken for detached value locations"
```

---

## Task 3: `DetachedScanContext` — AST-free scan context

**Files:**
- Create: `engine/src/main/java/com/ibm/engine/callstack/DetachedScanContext.java`
- Test: `engine/src/test/java/com/ibm/engine/callstack/DetachedScanContextTest.java`

**Interfaces:**
- Consumes: `IScanContext<R,T>` (`engine/.../language/IScanContext.java`).
- Produces: `DetachedScanContext<R,T>(InputFile inputFile, String filePath)` implementing `IScanContext`. `getFilePath()`/`getInputFile()` return the captured values; `reportIssue(...)` throws `UnsupportedOperationException` (never called on the production CBOM path — see spec risk audit in Task 12).

- [ ] **Step 1: Write the failing test.**
```java
/* <Apache header> */
package com.ibm.engine.callstack;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.sonar.api.batch.fs.InputFile;

class DetachedScanContextTest {
    @Test
    void exposesFilePathWithoutPinningAst() {
        InputFile inputFile = mock(InputFile.class);
        DetachedScanContext<Object, Object> ctx =
                new DetachedScanContext<>(inputFile, "/abs/path/CrossFileUsage.java");
        assertThat(ctx.getFilePath()).isEqualTo("/abs/path/CrossFileUsage.java");
        assertThat(ctx.getInputFile()).isSameAs(inputFile);
    }
}
```

- [ ] **Step 2: Run — verify it fails to compile.**
Run: `mvn test -pl engine -Dtest=DetachedScanContextTest`
Expected: FAIL — class missing.

- [ ] **Step 3: Implement.**
```java
/* <Apache header> */
package com.ibm.engine.callstack;

import com.ibm.engine.language.IScanContext;
import javax.annotation.Nonnull;
import org.sonar.api.batch.fs.InputFile;

/** AST-free {@link IScanContext}: retains only the file handle + path captured at record time,
 *  never the {@code JavaFileScannerContext}, so a detached record does not pin the file's AST. */
public record DetachedScanContext<R, T>(@Nonnull InputFile inputFile, @Nonnull String filePath)
        implements IScanContext<R, T> {
    @Override public void reportIssue(@Nonnull R currentRule, @Nonnull T tree, @Nonnull String message) {
        throw new UnsupportedOperationException("reportIssue is not available on a detached scan context");
    }
    @Nonnull @Override public InputFile getInputFile() { return inputFile; }
    @Nonnull @Override public String getFilePath() { return filePath; }
}
```

- [ ] **Step 4: Run — verify PASS.**
Run: `mvn test -pl engine -Dtest=DetachedScanContextTest`
Expected: PASS.

- [ ] **Step 5: Commit.**
```bash
mvn spotless:apply
git add engine/src/main/java/com/ibm/engine/callstack/DetachedScanContext.java engine/src/test/java/com/ibm/engine/callstack/DetachedScanContextTest.java
git commit -m "feat(engine): AST-free DetachedScanContext"
```

---

## Task 4: `ArgSnapshot` + `MethodMatcher.matchKeys` overload

**Files:**
- Create: `engine/src/main/java/com/ibm/engine/callstack/ArgSnapshot.java`
- Modify: `engine/src/main/java/com/ibm/engine/detection/MethodMatcher.java`
- Test: `engine/src/test/java/com/ibm/engine/detection/MethodMatcherKeysTest.java`

**Interfaces:**
- Produces: `ArgSnapshot(int index, List<ResolvedSnapshotValue> values)` and `ResolvedSnapshotValue(Object value, DetachedSyntaxToken location)`.
- Produces: `MethodMatcher.matchKeys(@Nonnull IType invokedObjectType, @Nonnull String methodName, @Nonnull List<IType> parameterTypes)` returning `boolean`, applying the same predicates as `match(...)` (`MethodMatcher.java:159`) without a tree.

- [ ] **Step 1: Write `ArgSnapshot` and `ResolvedSnapshotValue`** (plain records; no test needed — exercised via later tasks).
```java
/* <Apache header> */
package com.ibm.engine.callstack;

import java.util.List;
import javax.annotation.Nonnull;

public record ArgSnapshot(int index, @Nonnull List<ResolvedSnapshotValue> values) {
    public record ResolvedSnapshotValue(@Nonnull Object value, @Nonnull DetachedSyntaxToken location) {}
}
```

- [ ] **Step 2: Write the failing `matchKeys` test.** Read `MethodMatcher.java:31-160` first to reuse the exact predicate fields (`invokedObjectTypeString`, `methodName`, `parameterTypes`).
```java
/* <Apache header> */
package com.ibm.engine.detection;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Test;

class MethodMatcherKeysTest {
    @Test
    void matchesByKeysSameAsTree() {
        MethodMatcher<Object> matcher =
                new MethodMatcher<>("javax.crypto.Cipher", "getInstance",
                        new LinkedList<>(List.of("java.lang.String")));
        IType type = new SimpleTypeForTest("javax.crypto.Cipher");
        assertThat(matcher.matchKeys(type, "getInstance", List.of(new SimpleTypeForTest("java.lang.String"))))
                .isTrue();
        assertThat(matcher.matchKeys(type, "doFinal", List.of(new SimpleTypeForTest("java.lang.String"))))
                .isFalse();
    }
}
```
Add a tiny `SimpleTypeForTest implements IType` in the same test package if no test `IType` fake exists (check `engine/src/test/java/com/ibm/engine/detection/` first for an existing one and reuse it).

- [ ] **Step 3: Run — verify it fails.**
Run: `mvn test -pl engine -Dtest=MethodMatcherKeysTest`
Expected: FAIL — `matchKeys` missing.

- [ ] **Step 4: Implement `matchKeys`** by extracting the predicate tail of `match(...)`. In `MethodMatcher.java`, refactor `match(...)` (`:159`) to delegate:
```java
public boolean match(@Nonnull T expression, @Nonnull ILanguageTranslation<T> translation,
        @Nonnull MatchContext matchContext) {
    Optional<IType> invokedObjectType = translation.getInvokedObjectTypeString(matchContext, expression);
    Optional<String> invokedMethodName = translation.getMethodName(matchContext, expression);
    List<IType> param = translation.getMethodParameterTypes(matchContext, expression);
    if (invokedObjectType.isEmpty() || invokedMethodName.isEmpty()) {
        return false;
    }
    return matchKeysInternal(invokedObjectType.get(), invokedMethodName.get(), param,
            translation.supportsSubsetParameterMatching());
}

public boolean matchKeys(@Nonnull IType invokedObjectType, @Nonnull String methodName,
        @Nonnull List<IType> parameterTypes) {
    return matchKeysInternal(invokedObjectType, methodName, parameterTypes, false);
}

private boolean matchKeysInternal(@Nonnull IType invokedObjectType, @Nonnull String methodName,
        @Nonnull List<IType> param, boolean subsetParameterMatching) {
    boolean typeMatches = this.invokedObjectTypeString.test(invokedObjectType);
    boolean nameMatches = this.methodName.test(methodName);
    if (!typeMatches || !nameMatches) {
        return false;
    }
    if (methodName.equals("<init>") && !parameterTypesSerializable.isEmpty() && subsetParameterMatching) {
        return anyParameterMatches(param);
    }
    return this.parameterTypes.test(param);
}
```
(Detached calls are never constructors with subset matching, so `matchKeys` passes `false`.)

- [ ] **Step 5: Run — verify PASS and no regressions.**
Run: `mvn test -pl engine -Dtest=MethodMatcherKeysTest,MethodMatcherTest`
Expected: PASS (run the existing `MethodMatcher*` tests too; if none exist, run `mvn test -pl engine`).

- [ ] **Step 6: Commit.**
```bash
mvn spotless:apply
git add engine/src/main/java/com/ibm/engine/callstack/ArgSnapshot.java engine/src/main/java/com/ibm/engine/detection/MethodMatcher.java engine/src/test/java/com/ibm/engine/detection/MethodMatcherKeysTest.java
git commit -m "feat(engine): ArgSnapshot + MethodMatcher.matchKeys (tree-free match)"
```

---

## Task 5: `isDetachableCall` predicate in the language layer

**Files:**
- Modify: `engine/src/main/java/com/ibm/engine/language/ILanguageSupport.java`
- Modify: `engine/src/main/java/com/ibm/engine/language/java/JavaLanguageSupport.java`
- Test: `engine/src/test/java/com/ibm/engine/language/java/JavaIsDetachableCallTest.java`

**Interfaces:**
- Produces: `default boolean isDetachableCall(@Nonnull T tree) { return false; }` on `ILanguageSupport`.
- Produces: Java override — `true` iff `tree` is a `MethodInvocationTree` whose `methodSymbol().declaration() != null` (user method → could be hooked) AND no argument expression subtree contains a `NEW_ARRAY` node (the only factory-steered resolution case, `JavaDetectionEngine.java:275`); else `false`.

- [ ] **Step 1: Add the default to `ILanguageSupport`.** Find the interface method list and add:
```java
/** Whether a recorded call may be stored tree-free (detached) instead of retaining its AST.
 *  Default: conservative false (retain the tree). Only Java method invocations override. */
default boolean isDetachableCall(@Nonnull T tree) {
    return false;
}
```

- [ ] **Step 2: Write the failing Java test.**
```java
/* <Apache header> */
package com.ibm.engine.language.java;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.sonar.java.model.JParserTestUtils;
import org.sonar.plugins.java.api.tree.ClassTree;
import org.sonar.plugins.java.api.tree.CompilationUnitTree;
import org.sonar.plugins.java.api.tree.ExpressionStatementTree;
import org.sonar.plugins.java.api.tree.MethodTree;
import org.sonar.plugins.java.api.tree.Tree;

class JavaIsDetachableCallTest {
    private Tree firstStatementExpression(String body) {
        CompilationUnitTree cut = JParserTestUtils.parse(
                "class A { void m(String s){ " + body + " } byte[] b(){return null;} }");
        MethodTree m = (MethodTree) ((ClassTree) cut.types().get(0)).members().get(0);
        ExpressionStatementTree stmt = (ExpressionStatementTree) m.block().body().get(0);
        return stmt.expression();
    }

    @Test
    void literalArgIsDetachable() {
        JavaLanguageSupport support = new JavaLanguageSupport();
        // user method call: A.b() has a source declaration
        Tree call = firstStatementExpression("b();");
        assertThat(support.isDetachableCall(call)).isTrue();
    }

    @Test
    void arrayArgIsNotDetachable() {
        JavaLanguageSupport support = new JavaLanguageSupport();
        Tree call = firstStatementExpression("java.util.Arrays.toString(new byte[]{1,2});");
        assertThat(support.isDetachableCall(call)).isFalse();
    }
}
```
(If `JParserTestUtils` is not on the test classpath, mirror the parsing helper used by an existing `engine` Java test — check `engine/src/test/java/com/ibm/engine/language/java/` for the established parse utility and reuse it.)

- [ ] **Step 3: Run — verify it fails.**
Run: `mvn test -pl engine -Dtest=JavaIsDetachableCallTest`
Expected: FAIL — `isDetachableCall` not overridden / returns false for the literal case.

- [ ] **Step 4: Implement in `JavaLanguageSupport`.**
```java
@Override
public boolean isDetachableCall(@Nonnull Tree tree) {
    if (!(tree instanceof MethodInvocationTree invocation)) {
        return false;
    }
    if (invocation.methodSymbol().declaration() == null) {
        return false; // library method: cannot match any source-declared method hook anyway
    }
    for (ExpressionTree arg : invocation.arguments()) {
        if (containsNewArray(arg)) {
            return false; // SizeFactory-steered resolution — keep the tree (fallback)
        }
    }
    return true;
}

private static boolean containsNewArray(@Nonnull Tree tree) {
    if (tree.is(Tree.Kind.NEW_ARRAY)) {
        return true;
    }
    boolean[] found = {false};
    tree.accept(new org.sonar.plugins.java.api.tree.BaseTreeVisitor() {
        @Override public void visitNewArray(org.sonar.plugins.java.api.tree.NewArrayTree t) {
            found[0] = true;
        }
    });
    return found[0];
}
```
Add imports: `MethodInvocationTree`, `ExpressionTree`, `Tree`.

- [ ] **Step 5: Run — verify PASS.**
Run: `mvn test -pl engine -Dtest=JavaIsDetachableCallTest`
Expected: PASS.

- [ ] **Step 6: Commit.**
```bash
mvn spotless:apply
git add engine/src/main/java/com/ibm/engine/language/ILanguageSupport.java engine/src/main/java/com/ibm/engine/language/java/JavaLanguageSupport.java engine/src/test/java/com/ibm/engine/language/java/JavaIsDetachableCallTest.java
git commit -m "feat(engine): isDetachableCall predicate (Java method invocations, no NEW_ARRAY)"
```

---

## Task 6: Convert `CallContext` to a sealed interface with `RetainedCall` (pure refactor, no behavior change)

Make `CallContext` sealed with a single variant `RetainedCall`, updating every consumer of `.tree()`/`.publisher()`. Behavior is identical; all existing tests (incl. Task 1) stay green. This isolates the compile-breaking type change from any logic change.

**Files:**
- Modify: `engine/src/main/java/com/ibm/engine/callstack/CallContext.java`
- Create: `engine/src/main/java/com/ibm/engine/callstack/RetainedCall.java`
- Modify: `CallStackAgent.java`, `HookRepository.java`, `IHook.java`, `EnumHook.java`, `MethodInvocationHookWithParameterResolvement.java`, `MethodInvocationHookWithReturnResolvement.java`

**Interfaces:**
- Produces: `sealed interface CallContext<R,T> permits RetainedCall, DetachedCall` with `@Nonnull IScanContext<R,T> publisher()` and `@Nullable T tree()` (default-null; `RetainedCall` overrides with its tree). `DetachedCall` is added in Task 7 — declare it in `permits` now and create a temporary empty stub, or add `permits RetainedCall` here and widen in Task 7.
- Produces: `RetainedCall<R,T>(T tree, IScanContext<R,T> publisher) implements CallContext<R,T>` — `tree()` returns the tree.

- [ ] **Step 1: Turn `CallContext` into the sealed interface** (start with a single permit; Task 7 widens it):
```java
/* <existing header> */
package com.ibm.engine.callstack;

import com.ibm.engine.language.IScanContext;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public sealed interface CallContext<R, T> permits RetainedCall {
    @Nullable T tree();
    @Nonnull IScanContext<R, T> publisher();
}
```

- [ ] **Step 2: Create `RetainedCall`.**
```java
/* <Apache header> */
package com.ibm.engine.callstack;

import com.ibm.engine.language.IScanContext;
import javax.annotation.Nonnull;

public record RetainedCall<R, T>(@Nonnull T tree, @Nonnull IScanContext<R, T> publisher)
        implements CallContext<R, T> {}
```

- [ ] **Step 3: Update `CallStackAgent.addCall`** to build a `RetainedCall` and update the `visitedTreeObjects` guard (unchanged logic, new type). At `CallStackAgent.java:60`:
```java
final CallContext<R, T> callContext = new RetainedCall<>(tree, scanContext);
```
Everywhere `callContext.tree()` is used inside `CallStackAgent`, it remains valid (RetainedCall returns non-null).

- [ ] **Step 4: Update the remaining consumers** to construct/expect the interface. The only constructions are in `CallStackAgent`. `HookRepository.update` (`:115-121`) uses `callContext.tree()` and `callContext.publisher()` — both still compile (interface methods). `IHook.isInvocationOn(CallContext,...)` and the three hook impls call `callContext.tree()` — still compile. No signature changes needed; only the `new CallContext<>(...)` construction (now `new RetainedCall<>(...)`) changes. Grep to confirm no other `new CallContext<>` exists:
Run: `grep -rn "new CallContext" engine/src/main/java`
Expected: no results after the edit.

- [ ] **Step 5: Build + full engine/java tests — verify green (no behavior change).**
Run: `mvn test -pl engine && mvn test -pl java -Dtest=CrossFileHookDetachTest`
Expected: PASS (all engine tests + the Task 1 baseline).

- [ ] **Step 6: Commit.**
```bash
mvn spotless:apply
git add engine/src/main/java/com/ibm/engine/callstack/CallContext.java engine/src/main/java/com/ibm/engine/callstack/RetainedCall.java engine/src/main/java/com/ibm/engine/callstack/CallStackAgent.java
git commit -m "refactor(engine): CallContext -> sealed interface with RetainedCall variant"
```

---

## Task 7: Add the `DetachedCall` variant

**Files:**
- Create: `engine/src/main/java/com/ibm/engine/callstack/DetachedCall.java`
- Modify: `engine/src/main/java/com/ibm/engine/callstack/CallContext.java` (widen `permits`)
- Test: `engine/src/test/java/com/ibm/engine/callstack/DetachedCallTest.java`

**Interfaces:**
- Produces: `DetachedCall<R,T>(IType invokedObjectType, String methodName, List<IType> parameterTypes, List<ArgSnapshot> arguments, DetachedScanContext<R,T> publisher) implements CallContext<R,T>`. `tree()` returns `null`. Getter `arguments()`, `invokedObjectType()`, `methodName()`, `parameterTypes()`.

- [ ] **Step 1: Widen the sealed permit** in `CallContext.java`: `permits RetainedCall, DetachedCall`.

- [ ] **Step 2: Write the failing test.**
```java
/* <Apache header> */
package com.ibm.engine.callstack;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.ibm.engine.detection.IType;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.sonar.api.batch.fs.InputFile;

class DetachedCallTest {
    @Test
    void holdsNoTree() {
        DetachedScanContext<Object, Object> ctx =
                new DetachedScanContext<>(mock(InputFile.class), "/p/CrossFileUsage.java");
        DetachedCall<Object, Object> call =
                new DetachedCall<>(mock(IType.class), "make", List.of(), List.of(), ctx);
        assertThat(call.tree()).isNull();
        assertThat(call.publisher()).isSameAs(ctx);
        assertThat(call.methodName()).isEqualTo("make");
    }
}
```

- [ ] **Step 3: Run — verify it fails to compile.**
Run: `mvn test -pl engine -Dtest=DetachedCallTest`
Expected: FAIL — class missing.

- [ ] **Step 4: Implement `DetachedCall`.**
```java
/* <Apache header> */
package com.ibm.engine.callstack;

import com.ibm.engine.detection.IType;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public record DetachedCall<R, T>(
        @Nonnull IType invokedObjectType,
        @Nonnull String methodName,
        @Nonnull List<IType> parameterTypes,
        @Nonnull List<ArgSnapshot> arguments,
        @Nonnull DetachedScanContext<R, T> detachedPublisher)
        implements CallContext<R, T> {
    @Nullable @Override public T tree() { return null; }
    @Nonnull @Override public com.ibm.engine.language.IScanContext<R, T> publisher() {
        return detachedPublisher;
    }
}
```

- [ ] **Step 5: Run — verify PASS and engine stays green.**
Run: `mvn test -pl engine -Dtest=DetachedCallTest && mvn test -pl engine`
Expected: PASS.

- [ ] **Step 6: Commit.**
```bash
mvn spotless:apply
git add engine/src/main/java/com/ibm/engine/callstack/DetachedCall.java engine/src/main/java/com/ibm/engine/callstack/CallContext.java engine/src/test/java/com/ibm/engine/callstack/DetachedCallTest.java
git commit -m "feat(engine): DetachedCall variant (tree-free recorded call)"
```

---

## Task 8: Record-time production of `DetachedCall` in the Java engine

Decide detach at record time, pre-resolve arguments while the file is live, and store a `DetachedCall`; else a `RetainedCall`. Keeps matching/replay unchanged for now (Task 9 wires replay), so detached calls are recorded but a hook firing on one would still take the retained path — to keep tests green this task also makes `CallStackAgent` skip detached calls during match until Task 9. To avoid a green-but-lossy interim, **Tasks 8 and 9 are committed together** (see Task 9 Step 6); do Task 8 without an intermediate "all green" claim beyond compilation.

**Files:**
- Modify: `engine/src/main/java/com/ibm/engine/language/java/JavaDetectionEngine.java`
- Modify: `engine/src/main/java/com/ibm/engine/detection/Handler.java` (add `addRecordedCall`)
- Modify: `engine/src/main/java/com/ibm/engine/callstack/CallStackAgent.java` (accept a prebuilt `CallContext`)

**Interfaces:**
- Produces: `Handler.addRecordedCall(@Nonnull CallContext<R,T> recordedCall)` → delegates to `callStackAgent.add(recordedCall)`.
- Produces: `CallStackAgent.add(@Nonnull CallContext<R,T> callContext)` — keys off `methodName` for `DetachedCall`, off `getKeyFormT(tree)` for `RetainedCall`; same dedup/notify contract.
- Produces (Java engine): a `DetachedCall` whose `arguments` are built by pre-resolving each invocation argument with `resolveValuesInInnerScope(Object.class, arg, null)` and capturing each `ResolvedValue`'s value + a `DetachedSyntaxToken` computed via a new `captureLocation(Tree)` helper mirroring `JavaTranslator.getDetectionContextFrom`.

- [ ] **Step 1: Add `CallStackAgent.add(CallContext)`** alongside the existing `addCall(tree, scanContext)`. Extract a key helper that works for both variants:
```java
public void add(@Nonnull CallContext<R, T> callContext) {
    final Optional<Integer> keyOptional = keyOf(callContext);
    if (keyOptional.isEmpty()) {
        return;
    }
    if (addedToCallContext(keyOptional.get(), callContext)) {
        this.notify(callContext);
    }
}

private Optional<Integer> keyOf(@Nonnull CallContext<R, T> callContext) {
    if (callContext instanceof DetachedCall<R, T> detached) {
        return Optional.of(detached.methodName().hashCode());
    }
    final T tree = callContext.tree();
    return tree == null ? Optional.empty() : getKeyFormT(tree);
}
```
Change the dedup in `addedToCallContext` to guard on the tree only when present (detached calls dedup by identity of the record — always add):
```java
private boolean addedToCallContext(int key, @Nonnull CallContext<R, T> callContext) {
    final T tree = callContext.tree();
    if (tree != null) {
        if (visitedTreeObjects.contains(tree)) {
            return false;
        }
        visitedTreeObjects.add(tree);
    }
    invokedCallStack.compute(
            key,
            (k, v) -> {
                if (v == null) {
                    final ArrayList<CallContext<R, T>> list = new ArrayList<>();
                    list.add(callContext);
                    return list;
                }
                v.add(callContext);
                return v;
            });
    return true;
}
```
Keep `addCall(tree, scanContext)` delegating: `add(new RetainedCall<>(tree, scanContext));`. (Task 12 later removes `visitedTreeObjects`; keep it here so this task is behavior-preserving.)

- [ ] **Step 2: Add `Handler.addRecordedCall`** next to `addCallToCallStack` (`Handler.java:51`):
```java
public void addRecordedCall(@Nonnull CallContext<R, T> recordedCall) {
    this.callStackAgent.add(recordedCall);
}
```

- [ ] **Step 3: Add the `captureLocation` helper to `JavaDetectionEngine`** (mirrors `JavaTranslator.getDetectionContextFrom`, `JavaTranslator.java:170-224`, but returns a `DetachedSyntaxToken`). Read that method first and copy its token/keyword logic exactly:
```java
@Nullable
private DetachedSyntaxToken captureLocation(@Nonnull Tree location, @Nonnull String text) {
    SyntaxToken firstToken = location.firstToken();
    SyntaxToken lastToken = location.lastToken();
    if (firstToken == null || lastToken == null) {
        return null;
    }
    SyntaxToken locationToken = firstToken;
    List<String> keywords = List.of();
    // Keyword/additionalContext fidelity: for the common detached case the location is a literal
    // (default branch -> empty keywords), so implementing only `default` is correct for literals.
    // To match today's output when a resolved value's location is a NEW_CLASS / METHOD_INVOCATION /
    // ENUM_CONSTANT, replicate the three case bodies from JavaTranslator.getDetectionContextFrom
    // (JavaTranslator.java:179-216) verbatim here — they only read the live tree and produce the
    // `keywords` list + a more specific `locationToken`. Those Java-tree casts are available in the
    // engine module. Example for METHOD_INVOCATION:
    //   MethodInvocationTree mit = (MethodInvocationTree) location;
    //   SyntaxToken sel = mit.methodSelect().firstToken();
    //   if (sel != null) locationToken = sel;
    //   keywords = List.of(mit.methodSymbol().signature(), mit.methodSymbol().name());
    Position start = locationToken.range().start();
    Position end = lastToken.range().end();
    return new DetachedSyntaxToken(start.line(), start.columnOffset(), end.line(), end.columnOffset(),
            text, keywords);
}
```
Note the column convention: `Position.columnOffset()` is 0-based, matching `DetachedSyntaxToken`'s stored `columnOffset`. `DetectionLocation`'s `offset` is fed from `columnOffset()` today (`JavaTranslator.java:223`), so capture and store `columnOffset()` (0-based) consistently end to end.

- [ ] **Step 4: Build the variant in `JavaDetectionEngine.run`** at the method-invocation site (`JavaDetectionEngine.java:98-100`). Replace the unconditional `handler.addCallToCallStack(...)` with:
```java
MethodInvocationTree methodInvocationTree = (MethodInvocationTree) tree;
final IScanContext<JavaCheck, Tree> scanContext = detectionStore.getScanContext();
if (handler.getLanguageSupport().isDetachableCall(methodInvocationTree)) {
    final DetachedCall<JavaCheck, Tree> detached = buildDetachedCall(methodInvocationTree, scanContext);
    if (detached != null) {
        handler.addRecordedCall(detached);
    } else {
        handler.addCallToCallStack(methodInvocationTree, scanContext); // pre-resolution failed -> keep tree
    }
} else {
    handler.addCallToCallStack(methodInvocationTree, scanContext);
}
```
Leave the enum site (`:113-115`) calling `addCallToCallStack` unchanged (enums are never detached this iteration).

- [ ] **Step 5: Implement `buildDetachedCall`.** Uses the translation for match keys and `resolveValuesInInnerScope` for arguments; returns `null` if any argument fails to resolve or a location can't be captured (→ caller keeps the tree):
```java
@Nullable
private DetachedCall<JavaCheck, Tree> buildDetachedCall(
        @Nonnull MethodInvocationTree invocation, @Nonnull IScanContext<JavaCheck, Tree> scanContext) {
    final MatchContext matchContext = MatchContext.build(false, detectionStore.getDetectionRule());
    final ILanguageTranslation<Tree> translation = handler.getLanguageSupport().translation();
    final Optional<IType> invokedType = translation.getInvokedObjectTypeString(matchContext, invocation);
    final Optional<String> name = translation.getMethodName(matchContext, invocation);
    if (invokedType.isEmpty() || name.isEmpty()) {
        return null;
    }
    final List<IType> paramTypes = translation.getMethodParameterTypes(matchContext, invocation);

    final List<ArgSnapshot> args = new ArrayList<>();
    final List<ExpressionTree> arguments = invocation.arguments();
    for (int i = 0; i < arguments.size(); i++) {
        final List<ResolvedValue<Object, Tree>> resolved =
                resolveValuesInInnerScope(Object.class, arguments.get(i), null);
        final List<ArgSnapshot.ResolvedSnapshotValue> snapshots = new ArrayList<>();
        for (ResolvedValue<Object, Tree> rv : resolved) {
            final DetachedSyntaxToken loc = captureLocation(rv.tree(), rv.value().toString());
            if (loc == null) {
                return null; // cannot faithfully snapshot -> fall back to retained tree
            }
            snapshots.add(new ArgSnapshot.ResolvedSnapshotValue(rv.value(), loc));
        }
        args.add(new ArgSnapshot(i, snapshots));
    }

    final DetachedScanContext<JavaCheck, Tree> detachedCtx =
            new DetachedScanContext<>(scanContext.getInputFile(), scanContext.getFilePath());
    return new DetachedCall<>(invokedType.get(), name.get(), paramTypes, args, detachedCtx);
}
```
Add imports: `ArgSnapshot`, `DetachedCall`, `DetachedScanContext`, `DetachedSyntaxToken`, `ILanguageTranslation`, `IType`, `MatchContext`, `Position`, `SyntaxToken`, `ArrayList`, `List`, `Optional`.

- [ ] **Step 6: Compile only (replay lands in Task 9).**
Run: `mvn -q -pl engine test-compile`
Expected: compiles. (Do not run full tests here; matching still ignores detached records — Task 9 wires replay. Proceed directly to Task 9; commit is shared.)

---

## Task 9: Fire-time replay for `DetachedCall`

Make matching and hook-fire handle detached records so a `DetachedCall` produces the same detection value a `RetainedCall` would, then verify the Task 1 baseline passes with detachment live.

**Files:**
- Modify: `engine/src/main/java/com/ibm/engine/callstack/CallStackAgent.java` (`onNewHookSubscription` match)
- Modify: `engine/src/main/java/com/ibm/engine/hooks/HookRepository.java` (`update`)
- Modify: `engine/.../hooks/MethodInvocationHookWithParameterResolvement.java`, `EnumHook.java`, `MethodInvocationHookWithReturnResolvement.java`, `IHook.java` (`isInvocationOn(CallContext,...)`)
- Modify: `engine/.../hooks/HookDetectionObservable.java`, `IHookDetectionObserver.java`, `DetectionStore.java`, `DetectionStoreWithHook.java` (carry the `CallContext` through fire instead of a raw `T` tree)

**Interfaces:**
- Produces: `IHook.isInvocationOn(CallContext,...)` matches `DetachedCall` via `MethodMatcher.matchKeys(invokedObjectType, methodName, parameterTypes)` and `RetainedCall` via the existing tree `match(...)`.
- Produces: the fire path carries `CallContext<R,T>` (not `T invocationTree`) from `HookRepository.update` → `HookDetectionObservable.notify` → `IHookDetectionObserver.onHookInvocation` → `DetectionStoreWithHook`. Retained records behave exactly as before (`callContext.tree()`); detached records take the snapshot branch.

- [ ] **Step 1: Match keys in the hooks.** In `MethodInvocationHookWithParameterResolvement.isInvocationOn(CallContext,...)` (`:59-63`) and the return-resolvement equivalent, branch on the variant:
```java
@Override
public boolean isInvocationOn(@Nonnull CallContext<R, T> callContext,
        @Nonnull ILanguageSupport<R, T, S, P> languageSupport) {
    if (callContext instanceof DetachedCall<R, T> detached) {
        MethodMatcher<T> matcher = languageSupport.createMethodMatcherBasedOn(methodDefinition);
        return matcher != null
                && matcher.matchKeys(detached.invokedObjectType(), detached.methodName(),
                        detached.parameterTypes());
    }
    return isInvocationOn(callContext.tree(), languageSupport);
}
```
For `EnumHook.isInvocationOn(CallContext,...)`: detached calls are never enums, so `if (callContext instanceof DetachedCall) return false;` then fall through to the tree path.

- [ ] **Step 2: Match in `CallStackAgent.onNewHookSubscription`** (`:100-112`). Replace `methodMatcher.match(callContext.tree(), translation, matchContext)` with a variant-aware check:
```java
final boolean matches;
if (callContext instanceof DetachedCall<R, T> detached) {
    matches = methodMatcher.matchKeys(detached.invokedObjectType(), detached.methodName(),
            detached.parameterTypes());
} else {
    matches = methodMatcher.match(callContext.tree(), languageSupport.translation(), hook.matchContext());
}
if (matches) { stackCalls.add(callContext); }
```

- [ ] **Step 3: Carry the `CallContext` through the fire path.** Change signatures from `T invocationTree` to `CallContext<R,T> callContext`:
  - `HookRepository.update` (`:120-121`): `handler.notifyAllHookDetectionObservers(callContext, hook)` (drop the separate tree/publisher args).
  - `HookDetectionObservable.notify` (`:57-75`) + `IHookDetectionObservable`: take `CallContext<R,T> callContext`, call `subscribers.get(i).onHookInvocation(callContext, hook)`.
  - `IHookDetectionObserver.onHookInvocation` + `DetectionStore.onHookInvocation` (`:399-416`): take `CallContext<R,T> callContext`; build the child store with `callContext.publisher()` and pass `callContext` into `DetectionStoreWithHook`.
  - Update `Handler.notifyAllHookDetectionObservers` accordingly.
  - `DetectionStoreWithHook` stores `CallContext<R,T> callContext` instead of `T invocationTree`; `invocationTree` usages become `callContext.tree()` (retained) or the snapshot branch (detached).

- [ ] **Step 4: Detached branch in `DetectionStoreWithHook.handleMethodInvocationHookWithParameterResolvement`** (`:124-203`). When `callContext instanceof DetachedCall`, skip `extractArgumentFromMethodCaller`/`resolveValuesInInnerScope` and use the snapshot at the hook's parameter index:
```java
if (callContext instanceof DetachedCall<R, T> detached) {
    int idx = parameterIndex(hook.methodDefinition(), hook.methodParameter());
    if (idx < 0 || idx >= detached.arguments().size()) { return; }
    ArgSnapshot snap = detached.arguments().get(idx);
    if (hook.getParameter() instanceof DetectableParameter<T> detectableParameter) {
        for (ArgSnapshot.ResolvedSnapshotValue rv : snap.values()) {
            @SuppressWarnings("unchecked")
            T loc = (T) rv.location();
            ResolvedValue<Object, T> resolved = new ResolvedValue<>(rv.value(), loc);
            new ValueDetection<>(resolved, detectableParameter, loc, null)
                    .toValue(detectableParameter.getiValueFactory())
                    .ifPresent(iValue -> addValue(detectableParameter.getIndex(), iValue));
        }
    }
    handleNextRulesForMethodHooks(hook, /* traceSymbol */ null, isSuccessive);
    return;
}
// ... existing retained-tree logic unchanged ...
```
Add helper (index of the hook's parameter identifier within the method definition):
```java
private int parameterIndex(@Nonnull T methodDefinition, @Nonnull T methodParameter) {
    return handler.getLanguageSupport().parameterIndexOf(methodDefinition, methodParameter);
}
```
Add `parameterIndexOf(T methodDefinition, T methodParameter)` to `ILanguageSupport` (default `-1`) and implement for Java in `JavaLanguageSupport` by matching `methodParameter`'s name against `((MethodTree) methodDefinition).parameters()` simple names (reuse `translation().resolveIdentifierAsString`). Because `T loc` is a `DetachedSyntaxToken` (a `Tree`), the cast is safe for Java (`T = Tree`).

- [ ] **Step 5: Run the full engine suite + the cross-file baseline (now exercising the detached path).**
Run: `mvn test -pl engine && mvn test -pl java -Dtest=CrossFileHookDetachTest`
Expected: PASS. The Task 1 test now flows through `DetachedCall` (the `"AES/GCM/NoPadding"` literal resolves at record time). If it fails, log the recorded variant in `CallStackAgent.add` at DEBUG and confirm the usage call became a `DetachedCall` and the snapshot index maps to the `transformation` parameter.

- [ ] **Step 6: Commit Tasks 8 + 9 together.**
```bash
mvn spotless:apply
git add engine/src/main/java/com/ibm/engine java/  # staged engine + any java touch
git commit -m "feat(engine): produce and replay DetachedCall for Java method invocations"
```

---

## Task 10: `JavaTranslator` DetachedSyntaxToken branch (location fidelity)

**Files:**
- Modify: `java/src/main/java/com/ibm/plugin/translation/translator/JavaTranslator.java`
- Test: `java/src/test/java/com/ibm/plugin/translation/translator/JavaTranslatorDetachedLocationTest.java`

**Interfaces:**
- Consumes: `DetachedSyntaxToken` (engine).
- Produces: `getDetectionContextFrom` returns a `DetectionLocation` built directly from a `DetachedSyntaxToken` when the location is one.

- [ ] **Step 1: Write the failing test.**
```java
/* <Apache header> */
package com.ibm.plugin.translation.translator;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.callstack.DetachedSyntaxToken;
import com.ibm.mapper.model.IBundle;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class JavaTranslatorDetachedLocationTest {
    @Test
    void buildsLocationFromDetachedToken() {
        DetachedSyntaxToken token =
                new DetachedSyntaxToken(7, 2, 7, 9, "AES", List.of("kw"));
        DetectionLocation loc =
                new JavaTranslator().getDetectionContextFrom(token, Mockito.mock(IBundle.class), "F.java");
        assertThat(loc.lineNumber()).isEqualTo(7);
        assertThat(loc.keywords()).containsExactly("kw");
    }
}
```
(Confirm `DetectionLocation`'s accessor names via `mapper/.../DetectionLocation.java:26-31`; adjust `lineNumber()`/`keywords()` to the real record component names.)

- [ ] **Step 2: Run — verify it fails.**
Run: `mvn test -pl java -Dtest=JavaTranslatorDetachedLocationTest`
Expected: FAIL — falls through to token logic / empty keywords.

- [ ] **Step 3: Add the leading branch** to `getDetectionContextFrom` (`JavaTranslator.java:170`):
```java
@Nullable public DetectionLocation getDetectionContextFrom(
        @Nonnull Tree location, @Nonnull IBundle bundle, @Nonnull String filePath) {
    if (location instanceof DetachedSyntaxToken d) {
        return new DetectionLocation(filePath, d.line(), d.offset(), d.keywords(), bundle);
    }
    // ... existing logic unchanged ...
}
```
Add import `com.ibm.engine.callstack.DetachedSyntaxToken`.

- [ ] **Step 4: Run — verify PASS.**
Run: `mvn test -pl java -Dtest=JavaTranslatorDetachedLocationTest`
Expected: PASS.

- [ ] **Step 5: Commit.**
```bash
mvn spotless:apply
git add java/src/main/java/com/ibm/plugin/translation/translator/JavaTranslator.java java/src/test/java/com/ibm/plugin/translation/translator/JavaTranslatorDetachedLocationTest.java
git commit -m "feat(java): translate DetachedSyntaxToken locations directly"
```

---

## Task 11: End-to-end verification + `getLocation()` consumer audit

**Files:**
- Modify (if audit finds a gap): the offending consumer only.
- Test: extend `CrossFileHookDetachTest` with a NEW_ARRAY (tree-fallback) case.

- [ ] **Step 1: Add a fallback-path case to the cross-file test.** This exercises the `isDetachableCall == false` retained path across files (a `NEW_ARRAY` argument keeps the tree).

`java/src/test/files/rules/detection/crossfile/CrossFileIvDefinition.java`:
```java
package rules.detection.crossfile;

import javax.crypto.spec.IvParameterSpec;

public class CrossFileIvDefinition {
    public IvParameterSpec make(byte[] iv) {
        return new IvParameterSpec(iv); // NEW_ARRAY flows here -> retained (non-detachable) call
    }
}
```
`java/src/test/files/rules/detection/crossfile/CrossFileIvUsage.java`:
```java
package rules.detection.crossfile;

import javax.crypto.spec.IvParameterSpec;

public class CrossFileIvUsage {
    public IvParameterSpec use() {
        return new CrossFileIvDefinition().make(new byte[16]);
    }
}
```
Add a test method to `CrossFileHookDetachTest` (reuse its `collectValues`/`sawAes` pattern with a fresh flag `sawIv`, asserting an `IvParameterSpec`/nonce-related detection value is produced across the two files):
```java
private static boolean sawIv = false;

@Test
void crossFileArrayStillDetects() {
    sawIv = false;
    CheckVerifier.newVerifier()
            .onFiles(
                    "src/test/files/rules/detection/crossfile/CrossFileIvUsage.java",
                    "src/test/files/rules/detection/crossfile/CrossFileIvDefinition.java")
            .withCheck(this)
            .verifyNoIssues();
    assertThat(sawIv).as("cross-file retained (array) path still detects").isTrue();
}
```
In `collectValues`, also set `sawIv = true` when a value's class/asString indicates the IV/nonce detection (adjust the marker to whatever `JavaDetectionRules` emit for `IvParameterSpec`; run once and inspect the logged detection store to pick the exact value type).

- [ ] **Step 2: Run both cross-file cases.**
Run: `mvn test -pl java -Dtest=CrossFileHookDetachTest`
Expected: PASS (both literal-detached and array-retained resolve).

- [ ] **Step 3: Audit `getLocation()` consumers** (spec top risk). Confirm no consumer navigates `parent()`/`accept()`/children on a value location:
Run: `grep -rn "getLocation()" --include=*.java engine java mapper output enricher | grep -v /target/ | grep -v test`
Expected: only translator `getDetectionContextFrom` calls; if any consumer calls `.parent()`/`.accept()`/child accessors on a location, add a `DetachedSyntaxToken` guard there. Record the audit result in the commit message.

- [ ] **Step 4: Full suite green.**
Run: `mvn test -pl engine && mvn test -pl java`
Expected: PASS.

- [ ] **Step 5: Commit.**
```bash
mvn spotless:apply
git add java/src/test engine java  # only files actually changed
git commit -m "test: cross-file detach + retained-array cases; getLocation consumer audit"
```

---

## Task 12: Cleanup — remove redundant `visitedTreeObjects`

Measured 100% redundant with `invokedCallStack` retention. Dedup within the per-name bucket instead.

**Files:**
- Modify: `engine/src/main/java/com/ibm/engine/callstack/CallStackAgent.java`

- [ ] **Step 1: Replace the field-based dedup** (`CallStackAgent.java:45`, `:123-127`) with a per-bucket check. In `addedToCallContext`, for retained calls test membership in the bucket list by tree identity before appending; detached calls always append (distinct records):
```java
private boolean addedToCallContext(int key, @Nonnull CallContext<R, T> callContext) {
    final T tree = callContext.tree();
    final boolean[] added = {true};
    invokedCallStack.compute(key, (k, v) -> {
        List<CallContext<R, T>> list = (v == null) ? new ArrayList<>() : v;
        if (tree != null) {
            for (CallContext<R, T> existing : list) {
                if (tree.equals(existing.tree())) { added[0] = false; return list; }
            }
        }
        list.add(callContext);
        return list;
    });
    return added[0];
}
```
Delete the `visitedTreeObjects` field and its imports.

- [ ] **Step 2: Full engine + cross-file green.**
Run: `mvn test -pl engine && mvn test -pl java -Dtest=CrossFileHookDetachTest`
Expected: PASS.

- [ ] **Step 3: Commit.**
```bash
mvn spotless:apply
git add engine/src/main/java/com/ibm/engine/callstack/CallStackAgent.java
git commit -m "perf(engine): drop redundant visitedTreeObjects; dedup within bucket"
```

---

## Task 13: Cleanup — key-indexed subscription lookup

`onNewHookSubscription` currently scans all buckets (`CallStackAgent.java:101`). Look up only the bucket for the hook's method name.

**Files:**
- Modify: `engine/src/main/java/com/ibm/engine/callstack/CallStackAgent.java`

- [ ] **Step 1: Derive the name key from the hook and scan one bucket.** In `onNewHookSubscription`, after building `methodMatcher`, compute the hook's method-name key the same way records are keyed (`methodName.hashCode()` for detached, `getKeyFormT` for retained) and iterate only `invokedCallStack.get(key)`. If the hook's method name isn't statically known (multi-name/`ANY` matcher), fall back to scanning `invokedCallStack.values()` as today. Obtain the name from `languageSupport.translation().getMethodName(hook.matchContext(), hook.hookValue())`; if empty, use the fallback scan.
```java
final Optional<String> hookName =
        languageSupport.translation().getMethodName(hook.matchContext(), hook.hookValue());
final Collection<List<CallContext<R, T>>> buckets =
        hookName.map(n -> invokedCallStack.getOrDefault(n.hashCode(), List.of()))
                .map(List::of)
                .map(l -> (Collection<List<CallContext<R, T>>>) l)
                .orElseGet(invokedCallStack::values);
```
Then iterate `buckets` with the existing match logic (Task 9 Step 2). Keep the fallback correct for hooks whose name resolves differently than the record key.

- [ ] **Step 2: Full engine + cross-file green** (the Task 1 test registers the hook in the definition file and must still find the usage-file record via the keyed bucket).
Run: `mvn test -pl engine && mvn test -pl java -Dtest=CrossFileHookDetachTest`
Expected: PASS.

- [ ] **Step 3: Commit.**
```bash
mvn spotless:apply
git add engine/src/main/java/com/ibm/engine/callstack/CallStackAgent.java
git commit -m "perf(engine): key-indexed subscription lookup in CallStackAgent"
```

---

## Task 14: Heap measurement + docs

**Files:**
- Modify: `docs/TROUBLESHOOTING.md` (append a short note referencing the measurement)

- [ ] **Step 1: Full build + all module tests.**
Run: `mvn clean test`
Expected: PASS across all modules.

- [ ] **Step 2: Measure heap on a large compiled project.** Use the keycloak repro from the memory note (`mvn sonar:sonar` so types resolve; source-only scans fire `addCall` zero times). Constrain the scanner heap and capture before/after:
```bash
MAVEN_OPTS="-Xmx4g" mvn -o sonar:sonar -Dsonar.host.url=... 2>&1 | tee scan.log
# in another shell, sample the scanner JVM:
jmap -histo <pid> | grep -E "CallContext|DetachedCall|RetainedCall|Tree" | head
```
Record retained `RetainedCall` vs `DetachedCall` counts and peak used heap; compare to the ~179k `CallContext` / ~7 GB baseline in `docs/superpowers/plans/2026-07-05-callstack-hooks-heap-reduction.md`.

- [ ] **Step 3: Write the result** as a short paragraph in `docs/TROUBLESHOOTING.md` (retained vs detached split, peak-heap delta). If detached share is low, note it (candidate follow-ups: enum detachment, array pre-resolution).

- [ ] **Step 4: Commit.**
```bash
git add docs/TROUBLESHOOTING.md
git commit -m "docs: record call-stack detach heap measurement"
```

---

## Self-review notes (coverage map)

- Spec §"Match" → Task 4 (`matchKeys`), Task 9 Steps 1–2.
- Spec §"Resolution input" (record-time pre-resolution, NEW_ARRAY fallback, expressionToResolve n/a for Java) → Task 5 (predicate), Task 8 (`buildDetachedCall`), Task 9 Step 4 (snapshot replay).
- Spec §"Detection output / synthetic token" → Task 2, Task 10.
- Spec §"scanContext gap" → Task 3, Task 8 Step 5, Task 9 Step 3.
- Spec §"Hybrid detach with tree-fallback" → Task 5 + Task 8 Step 4 (retained fallback paths).
- Spec §"Lossless cleanups" → Task 12 (visitedTreeObjects), Task 13 (key-indexed lookup).
- Spec §"Verification" → Task 1 (baseline), Task 11 (both paths + consumer audit), Task 14 (heap profile).
- Spec §"out of scope" (Python/Go, enums, caps) → enforced by default-`false` predicate; enum site left on `addCallToCallStack` (Task 8 Step 4).
