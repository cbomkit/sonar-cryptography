# Call-Stack Heap/Perf Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a self-contained, manual-on-demand JUnit test that generates a large synthetic cross-file crypto corpus, scans it in-process, and deterministically asserts that recorded calls are detached (per-file ASTs released) at `leaveFile` — the signature of the `feat/callstack-ast-detach` fix — while reporting heap/time for manual inspection.

**Architecture:** Add a small read-only introspection accessor (`CallContextStats`) threaded down the existing `CallStackAgent → Handler → ILanguageSupport → JavaLanguageSupport` chain (the same chain that already carries `detachCallsForFile`/`notifyLeaveFile`). A test-only `CryptoCorpusGenerator` writes N wrapper/caller `.java` unit pairs to a temp dir; a `@Tag("performance")` test compiles them to a classpath dir and scans them with sonar-java `CheckVerifier` (the proven `CrossFileHookDetachTest` driving path — compiling + classpath is what makes callee types resolve so cross-file detections fire and calls get recorded). After the scan it reads `CallContextStats` and asserts a structural invariant (tree-pinning calls stay bounded; detached ratio high). The tag is excluded from the default build via surefire.

**Tech Stack:** Java 17, Maven multi-module, JUnit 5 + AssertJ + Mockito 5.17, sonar-java `CheckVerifier` (java-checks-testkit 8.15), Google Java Format (Spotless, AOSP), Checkstyle.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-07-06-callstack-heap-perf-harness-design.md`.
- **Before every commit:** `mvn spotless:apply` then `mvn checkstyle:check` must succeed. Apache 2.0 license header required in every new `.java` file (Spotless applies it from the configured header; run `spotless:apply` and commit the result). `@Override` required where overriding; no unused imports; camelCase params.
- **Watch out — `spotless:apply` intermittently truncates `mapper/.../JsonCipherSuites.java`.** If `git status` after formatting shows that file changed and you did not touch it, restore it (`git checkout -- mapper/src/main/resources/**/JsonCipherSuites.json` / the generated file) before committing. Do not commit a truncated `JsonCipherSuites`.
- **Never weaken or delete an assertion to make a build pass.** The perf test's thresholds are tuned once against observed numbers (Task 4) and then fixed.
- **The perf test must never gate CI** — it is `@Tag("performance")` and excluded from the default build. Only `mvn test` staying green (perf skipped) is required for CI; the perf test is run manually.
- **Determinism:** the perf test asserts only on `CallContextStats` counts (object-variant counts in the call stack), never on measured heap MB or wall-time. Heap/time are printed, never asserted.
- **DetectionLocation for engine tests (if needed):** `new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "TEST")`.

---

### Task 1: `CallContextStats` record + counting logic

Add the immutable stats record and its pure counting factory in the `engine` module. This is the data the perf test asserts on. The factory is the only non-trivial logic, so it is what the unit test targets.

**Files:**
- Create: `engine/src/main/java/com/ibm/engine/callstack/CallContextStats.java`
- Test: `engine/src/test/java/com/ibm/engine/callstack/CallContextStatsTest.java`

**Interfaces:**
- Consumes: existing `CallContext<R,T>` (sealed), `RetainedCall<R,T>` (`@Nonnull T tree()`), `DetachedCall<R,T>` (`tree()` returns `null`), all in `com.ibm.engine.callstack`.
- Produces:
  - `public record CallContextStats(int retainedWithTree, int detached, int total, int buckets)`
  - `public static final CallContextStats CallContextStats.EMPTY`
  - `public double CallContextStats.detachedRatio()` — `detached/total`, or `1.0` when `total == 0`.
  - `public static <R,T> CallContextStats CallContextStats.from(Collection<List<CallContext<R,T>>> buckets)`

- [ ] **Step 1: Write the failing test**

Create `engine/src/test/java/com/ibm/engine/callstack/CallContextStatsTest.java` (license header added by `spotless:apply` in Step 4):

```java
package com.ibm.engine.callstack;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.mockito.Mockito.mock;

import com.ibm.engine.language.IScanContext;
import java.util.List;
import org.junit.jupiter.api.Test;

class CallContextStatsTest {

    @Test
    @SuppressWarnings("unchecked")
    void countsRetainedAndDetachedAcrossBuckets() {
        IScanContext<Object, String> ctx = mock(IScanContext.class);
        RetainedCall<Object, String> retained1 = new RetainedCall<>("t1", ctx, null);
        RetainedCall<Object, String> retained2 = new RetainedCall<>("t2", ctx, null);
        DetachedCall<Object, String> detached = mock(DetachedCall.class);

        List<List<CallContext<Object, String>>> buckets =
                List.of(List.of(retained1, detached), List.of(retained2));

        CallContextStats stats = CallContextStats.from(buckets);

        assertThat(stats.retainedWithTree()).isEqualTo(2);
        assertThat(stats.detached()).isEqualTo(1);
        assertThat(stats.total()).isEqualTo(3);
        assertThat(stats.buckets()).isEqualTo(2);
        assertThat(stats.detachedRatio()).isCloseTo(1.0d / 3.0d, within(1e-9));
    }

    @Test
    void emptyHasZeroCountsAndFullRatio() {
        assertThat(CallContextStats.EMPTY.total()).isZero();
        assertThat(CallContextStats.EMPTY.buckets()).isZero();
        assertThat(CallContextStats.EMPTY.detachedRatio()).isEqualTo(1.0d);
    }
}
```

Note: `DetachedCall` is a `record` (final); Mockito 5.17's default inline mock maker mocks it fine. The counting checks `instanceof DetachedCall` first and never calls a method on the mock, so no stubbing is needed.

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl engine -Dtest=CallContextStatsTest`
Expected: FAIL — compilation error, `CallContextStats` does not exist.

- [ ] **Step 3: Create the record + factory**

Create `engine/src/main/java/com/ibm/engine/callstack/CallContextStats.java`:

```java
package com.ibm.engine.callstack;

import java.util.Collection;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Immutable snapshot of the {@link CallStackAgent}'s recorded-call population, used by the
 * performance/heap harness to assert that calls were detached (ASTs released) at {@code leaveFile}.
 *
 * @param retainedWithTree number of {@link RetainedCall}s still pinning a live AST tree
 * @param detached number of tree-free {@link DetachedCall}s
 * @param total {@code retainedWithTree + detached}
 * @param buckets number of hash buckets in the call stack
 */
public record CallContextStats(int retainedWithTree, int detached, int total, int buckets) {

    /** A zero-valued snapshot (used as the language-agnostic default). */
    public static final CallContextStats EMPTY = new CallContextStats(0, 0, 0, 0);

    /** Fraction of recorded calls that are detached; {@code 1.0} when nothing was recorded. */
    public double detachedRatio() {
        return total == 0 ? 1.0d : (double) detached / (double) total;
    }

    /** Counts retained-with-tree vs. detached calls across all call-stack buckets. */
    @Nonnull
    public static <R, T> CallContextStats from(
            @Nonnull Collection<List<CallContext<R, T>>> buckets) {
        int retainedWithTree = 0;
        int detached = 0;
        for (List<CallContext<R, T>> bucket : buckets) {
            for (CallContext<R, T> call : bucket) {
                if (call instanceof DetachedCall<R, T>) {
                    detached++;
                } else if (call instanceof RetainedCall<R, T> retained && retained.tree() != null) {
                    retainedWithTree++;
                }
            }
        }
        return new CallContextStats(
                retainedWithTree, detached, retainedWithTree + detached, buckets.size());
    }
}
```

- [ ] **Step 4: Format, then run the test to verify it passes**

Run: `mvn spotless:apply -pl engine && mvn test -pl engine -Dtest=CallContextStatsTest`
Expected: PASS (2 tests). If `git status` shows an unrelated `JsonCipherSuites` change, restore it (see Global Constraints).

- [ ] **Step 5: Checkstyle + commit**

```bash
mvn checkstyle:check -pl engine
git add engine/src/main/java/com/ibm/engine/callstack/CallContextStats.java \
        engine/src/test/java/com/ibm/engine/callstack/CallContextStatsTest.java
git commit -m "feat(engine): CallContextStats accessor for call-stack retention"
```

---

### Task 2: Expose stats through `CallStackAgent → Handler → ILanguageSupport → JavaLanguageSupport`

Thread a `callContextStats()` accessor down the existing chain so a test can read the populated stats after a scan via `JavaAggregator.getLanguageSupport()`. Default interface method returns `EMPTY` (Go/Python untouched); `JavaLanguageSupport` overrides to delegate to its `Handler`.

**Files:**
- Modify: `engine/src/main/java/com/ibm/engine/callstack/CallStackAgent.java`
- Modify: `engine/src/main/java/com/ibm/engine/detection/Handler.java`
- Modify: `engine/src/main/java/com/ibm/engine/language/ILanguageSupport.java`
- Modify: `engine/src/main/java/com/ibm/engine/language/java/JavaLanguageSupport.java`
- Test: `engine/src/test/java/com/ibm/engine/language/java/JavaLanguageSupportStatsTest.java`

**Interfaces:**
- Consumes: `CallContextStats` and `CallContextStats.from(...)` (Task 1); existing `CallStackAgent.invokedCallStack` (private `ConcurrentMap<Integer, List<CallContext<R,T>>>`); `Handler.callStackAgent`; `JavaLanguageSupport.handler`; `LanguageSupporter.javaLanguageSupporter()`.
- Produces:
  - `public @Nonnull CallContextStats CallStackAgent.callContextStats()`
  - `public @Nonnull CallContextStats Handler.callContextStats()`
  - `default @Nonnull CallContextStats ILanguageSupport.callContextStats()` → `CallContextStats.EMPTY`
  - `@Override public @Nonnull CallContextStats JavaLanguageSupport.callContextStats()` → `handler.callContextStats()`

- [ ] **Step 1: Write the failing test**

Create `engine/src/test/java/com/ibm/engine/language/java/JavaLanguageSupportStatsTest.java`:

```java
package com.ibm.engine.language.java;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.callstack.CallContextStats;
import com.ibm.engine.language.ILanguageSupport;
import com.ibm.engine.language.LanguageSupporter;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class JavaLanguageSupportStatsTest {

    @Test
    void freshSupportReportsEmptyStatsThroughTheChain() {
        ILanguageSupport<JavaCheck, Tree, Symbol, JavaFileScannerContext> support =
                LanguageSupporter.javaLanguageSupporter();

        CallContextStats stats = support.callContextStats();

        assertThat(stats).isNotNull();
        assertThat(stats.total()).isZero();
        assertThat(stats.retainedWithTree()).isZero();
        assertThat(stats.detached()).isZero();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl engine -Dtest=JavaLanguageSupportStatsTest`
Expected: FAIL — compilation error, `ILanguageSupport.callContextStats()` does not exist.

- [ ] **Step 3: Add the accessor to `CallStackAgent`**

In `engine/src/main/java/com/ibm/engine/callstack/CallStackAgent.java`, add this method (e.g. directly after `detachCallsForFile`, around line 75). Same package as `CallContextStats`, so no import needed:

```java
    /** Read-only snapshot of the recorded-call population (retained-with-tree vs. detached). */
    @Nonnull
    public CallContextStats callContextStats() {
        return CallContextStats.from(invokedCallStack.values());
    }
```

- [ ] **Step 4: Add the delegating accessor to `Handler`**

In `engine/src/main/java/com/ibm/engine/detection/Handler.java`, add the import `import com.ibm.engine.callstack.CallContextStats;` (with the other `com.ibm.engine.callstack.*` imports) and this method (near `detachCallsForFile`, around line 90):

```java
    @Nonnull
    public CallContextStats callContextStats() {
        return this.callStackAgent.callContextStats();
    }
```

- [ ] **Step 5: Add the default method to `ILanguageSupport`**

In `engine/src/main/java/com/ibm/engine/language/ILanguageSupport.java`, add the import `import com.ibm.engine.callstack.CallContextStats;` and, next to the `notifyLeaveFile` default (around line 155), add:

```java
    /**
     * Read-only snapshot of the language's recorded-call population, for the performance/heap
     * harness. Languages that do not accumulate a call stack return {@link CallContextStats#EMPTY}.
     *
     * @return the current call-context stats; never {@code null}
     */
    @Nonnull
    default CallContextStats callContextStats() {
        return CallContextStats.EMPTY;
    }
```

- [ ] **Step 6: Override in `JavaLanguageSupport`**

In `engine/src/main/java/com/ibm/engine/language/java/JavaLanguageSupport.java`, add the import `import com.ibm.engine.callstack.CallContextStats;` and, next to the `notifyLeaveFile` override (around line 148), add:

```java
    @Override
    @Nonnull
    public CallContextStats callContextStats() {
        return this.handler.callContextStats();
    }
```

- [ ] **Step 7: Format, then run the test to verify it passes**

Run: `mvn spotless:apply -pl engine && mvn test -pl engine -Dtest=JavaLanguageSupportStatsTest`
Expected: PASS (1 test).

- [ ] **Step 8: Regression + checkstyle + commit**

Run: `mvn test -pl engine` (whole engine suite still green), then `mvn checkstyle:check -pl engine`.

```bash
git add engine/src/main/java/com/ibm/engine/callstack/CallStackAgent.java \
        engine/src/main/java/com/ibm/engine/detection/Handler.java \
        engine/src/main/java/com/ibm/engine/language/ILanguageSupport.java \
        engine/src/main/java/com/ibm/engine/language/java/JavaLanguageSupport.java \
        engine/src/test/java/com/ibm/engine/language/java/JavaLanguageSupportStatsTest.java
git commit -m "feat(engine): expose callContextStats through Handler/ILanguageSupport"
```

---

### Task 3: `CryptoCorpusGenerator` (synthetic cross-file corpus)

A test-only helper in the `java` module that writes N wrapper/caller unit pairs into a directory. Each unit is a `WrapperK` (crypto factory method taking an `algo` parameter → forces a method hook) and a `CallerK` (invokes the wrapper cross-file with a string literal and a field constant → detachable recorded calls). Distinct class names per unit keep call sites distinct so retention grows with corpus size. Uses only JDK `javax.crypto`/`java.security` APIs (JCA, 100% supported) so the corpus compiles with the system compiler and resolves in sonar-java's semantic model.

**Files:**
- Create: `java/src/test/java/com/ibm/plugin/perf/CryptoCorpusGenerator.java`
- Test: `java/src/test/java/com/ibm/plugin/perf/CryptoCorpusGeneratorTest.java`

**Interfaces:**
- Produces: `static List<Path> CryptoCorpusGenerator.generate(Path root, int units) throws IOException` — writes `2*units` files under `root/perf/` and returns their paths (wrapper then caller, per unit).

- [ ] **Step 1: Write the failing test**

Create `java/src/test/java/com/ibm/plugin/perf/CryptoCorpusGeneratorTest.java`:

```java
package com.ibm.plugin.perf;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CryptoCorpusGeneratorTest {

    @Test
    void generatesTwoFilesPerUnitThatCompile(@TempDir Path tmp) throws Exception {
        List<Path> files = CryptoCorpusGenerator.generate(tmp, 3);

        assertThat(files).hasSize(6);
        assertThat(files).allSatisfy(p -> assertThat(Files.exists(p)).isTrue());

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        List<String> args = new ArrayList<>(List.of("-d", tmp.resolve("out").toString()));
        files.forEach(p -> args.add(p.toAbsolutePath().toString()));
        int rc = compiler.run(null, null, null, args.toArray(new String[0]));

        assertThat(rc).as("generated corpus must compile cleanly").isZero();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl java -Dtest=CryptoCorpusGeneratorTest`
Expected: FAIL — compilation error, `CryptoCorpusGenerator` does not exist.

- [ ] **Step 3: Create the generator**

Create `java/src/test/java/com/ibm/plugin/perf/CryptoCorpusGenerator.java`:

```java
package com.ibm.plugin.perf;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Generates a synthetic corpus of cross-file crypto wrapper/caller unit pairs for the call-stack
 * heap harness. Each unit is a {@code WrapperK} whose factory method takes the algorithm as a
 * parameter (forcing a cross-file method hook) and a {@code CallerK} that invokes it with a string
 * literal and a field constant (both detachable recorded calls). Distinct class names per unit keep
 * call sites distinct so the recorded-call set grows with corpus size, approximating a large project
 * without checking one in. Uses only JDK JCA APIs so the corpus compiles and resolves.
 */
final class CryptoCorpusGenerator {

    private CryptoCorpusGenerator() {}

    /** A JCA factory rotated across units so multiple detection rules fire. */
    private record Api(@Nonnull String call, @Nonnull String algo) {}

    private static final List<Api> APIS =
            List.of(
                    new Api("javax.crypto.Cipher.getInstance(algo)", "AES"),
                    new Api("javax.crypto.KeyGenerator.getInstance(algo)", "AES"),
                    new Api("java.security.MessageDigest.getInstance(algo)", "SHA-256"));

    @Nonnull
    static List<Path> generate(@Nonnull Path root, int units) throws IOException {
        Path pkg = Files.createDirectories(root.resolve("perf"));
        List<Path> files = new ArrayList<>();
        for (int i = 0; i < units; i++) {
            Api api = APIS.get(i % APIS.size());

            Path wrapper = pkg.resolve("Wrapper" + i + ".java");
            Files.writeString(wrapper, wrapperSource(i, api));
            files.add(wrapper);

            Path caller = pkg.resolve("Caller" + i + ".java");
            Files.writeString(caller, callerSource(i, api));
            files.add(caller);
        }
        return files;
    }

    @Nonnull
    private static String wrapperSource(int i, @Nonnull Api api) {
        return "package perf;\n\n"
                + "public class Wrapper" + i + " {\n"
                + "    public Object make(String algo) throws Exception {\n"
                + "        return " + api.call() + ";\n"
                + "    }\n"
                + "}\n";
    }

    @Nonnull
    private static String callerSource(int i, @Nonnull Api api) {
        return "package perf;\n\n"
                + "public class Caller" + i + " {\n"
                + "    static final String ALGO = \"" + api.algo() + "\";\n"
                + "    void run() throws Exception {\n"
                + "        new Wrapper" + i + "().make(\"" + api.algo() + "\");\n"
                + "        new Wrapper" + i + "().make(ALGO);\n"
                + "    }\n"
                + "}\n";
    }
}
```

- [ ] **Step 4: Format, then run the test to verify it passes**

Run: `mvn spotless:apply -pl java && mvn test -pl java -Dtest=CryptoCorpusGeneratorTest`
Expected: PASS (1 test).

- [ ] **Step 5: Checkstyle + commit**

```bash
mvn checkstyle:check -pl java
git add java/src/test/java/com/ibm/plugin/perf/CryptoCorpusGenerator.java \
        java/src/test/java/com/ibm/plugin/perf/CryptoCorpusGeneratorTest.java
git commit -m "test(java): synthetic cross-file crypto corpus generator"
```

---

### Task 4: `CallStackHeapPerfTest` + surefire tag exclusion + threshold tuning

Add the `@Tag("performance")` harness that ties it together, exclude the tag from the default build, tune the assertion thresholds against observed numbers, and validate that the assertion actually discriminates (fails when detach is neutralized).

**Files:**
- Modify: `pom.xml` (parent — surefire `excludedGroups` via overridable property)
- Create: `java/src/test/java/com/ibm/plugin/perf/CallStackHeapPerfTest.java`

**Interfaces:**
- Consumes: `CryptoCorpusGenerator.generate(Path, int)` (Task 3); `JavaAggregator.getLanguageSupport().callContextStats()` (Task 2) returning `CallContextStats`; `TestBase` (`asserts(...)` abstract, `report(Tree, List<INode>)` overridable → controls issues raised); `CheckVerifier` (`onFiles(Collection<String>)`, `withClassPath(Collection<File>)`, `withChecks(JavaFileScanner...)`, `verifyNoIssues()`).

- [ ] **Step 1: Make surefire exclude the `performance` tag (overridable)**

In the parent `pom.xml`, add a property (in the existing `<properties>` block) that defaults the exclusion on:

```xml
        <excludedGroups>performance</excludedGroups>
```

and give the `maven-surefire-plugin` (currently declared with no `<configuration>`, around line 192) a configuration that reads it:

```xml
            <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-surefire-plugin</artifactId>
            <version>3.5.4</version>
            <configuration>
                <excludedGroups>${excludedGroups}</excludedGroups>
            </configuration>
            </plugin>
```

Effect: `mvn test` excludes `performance` (property from the pom). To run the perf test, a CLI `-DexcludedGroups=` overrides the pom property to empty (CLI system properties win over pom `<properties>`), re-including it.

- [ ] **Step 2: Verify the default build skips tagged tests (no perf test yet — use a temporary probe)**

Create a throwaway probe to prove exclusion works before writing the real test. Create `java/src/test/java/com/ibm/plugin/perf/TagExclusionProbe.java`:

```java
package com.ibm.plugin.perf;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

class TagExclusionProbe {
    @Tag("performance")
    @Test
    void taggedTestMustBeExcludedByDefault() {
        throw new AssertionError("this @Tag(performance) test must NOT run in the default build");
    }
}
```

Run (default build must NOT execute it, so it must stay green):
`mvn test -pl java -Dtest=TagExclusionProbe`
Expected: BUILD SUCCESS with "No tests were executed" (or 0 run) — the tag is excluded.

Then confirm it DOES run when exclusion is cleared, and fails as written:
`mvn test -pl java -DexcludedGroups= -Dtest=TagExclusionProbe`
Expected: FAIL with the `AssertionError` above — proving `-DexcludedGroups=` re-includes tagged tests.

Delete the probe: `rm java/src/test/java/com/ibm/plugin/perf/TagExclusionProbe.java`

- [ ] **Step 3: Commit the surefire change**

```bash
mvn spotless:apply
git add pom.xml
git commit -m "build: exclude @Tag(performance) tests from default surefire run"
```

- [ ] **Step 4: Write the perf harness test**

Create `java/src/test/java/com/ibm/plugin/perf/CallStackHeapPerfTest.java`. Starting thresholds are intentionally loose (`detachedRatio >= 0.5`, `retainedWithTree <= units`); Step 6 tightens them against observed numbers.

```java
package com.ibm.plugin.perf;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.callstack.CallContextStats;
import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.JavaAggregator;
import com.ibm.plugin.TestBase;
import com.ibm.rules.issue.Issue;
import java.io.File;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

/**
 * Manual heap/perf harness for the call-stack AST-detach mechanism. Generates a synthetic
 * cross-file crypto corpus (scale via {@code -Dperf.corpus.files}, default 200), scans it in-process
 * through {@link CheckVerifier} (compiled to a classpath dir so callee types resolve and cross-file
 * detections fire), then asserts the recorded calls were detached (ASTs released) at {@code
 * leaveFile}. Heap delta and wall-time are printed for manual comparison, never asserted.
 *
 * <p>Excluded from the default build via {@code @Tag("performance")}. Run with:
 * {@code mvn test -pl java -DexcludedGroups= -Dtest=CallStackHeapPerfTest} (add
 * {@code -Dperf.corpus.files=3000} for a heavy soak). This does NOT reproduce the full-project ~7 GB
 * keycloak number — that remains the documented manual {@code mvn sonar:sonar} route in
 * {@code docs/superpowers/plans/2026-07-05-callstack-hooks-heap-reduction.md}.
 */
@Tag("performance")
class CallStackHeapPerfTest extends TestBase {

    private static final int FILES = Integer.getInteger("perf.corpus.files", 200);

    /** Raise no SonarQube issues, so the harness is decoupled from {@code // Noncompliant} lines. */
    @Override
    public List<Issue<Tree>> report(@Nonnull Tree markerTree, @Nonnull List<INode> translatedNodes) {
        return List.of();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        // no per-finding assertions; the harness asserts on aggregate CallContextStats below
    }

    @Test
    void detachesRecordedCallsAtScale(@TempDir Path tmp) throws Exception {
        int units = Math.max(1, FILES / 2);
        List<Path> sources = CryptoCorpusGenerator.generate(tmp, units);
        File classes = compileToClasspath(sources);

        MemoryMXBean mem = ManagementFactory.getMemoryMXBean();
        long heapBefore = usedHeapAfterGc(mem);
        long start = System.nanoTime();

        CheckVerifier.newVerifier()
                .onFiles(absolutePaths(sources))
                .withClassPath(List.of(classes))
                .withChecks(this)
                .verifyNoIssues();

        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;
        long heapAfter = usedHeapAfterGc(mem);

        CallContextStats stats = JavaAggregator.getLanguageSupport().callContextStats();

        // REPORT (never asserted)
        System.out.printf(
                "%n[callstack-perf] files=%d units=%d time=%dms heapDeltaMB=%d "
                        + "retainedWithTree=%d detached=%d total=%d buckets=%d ratio=%.3f%n",
                sources.size(),
                units,
                elapsedMs,
                (heapAfter - heapBefore) / (1024L * 1024L),
                stats.retainedWithTree(),
                stats.detached(),
                stats.total(),
                stats.buckets(),
                stats.detachedRatio());

        // ASSERT (deterministic gate — object-variant counts, no heap/time dependence)
        assertThat(stats.total())
                .as("detections must fire (compiled classpath) or the harness proves nothing")
                .isPositive();
        assertThat(stats.detachedRatio())
                .as("most recorded calls must be detached (ASTs released at leaveFile)")
                .isGreaterThanOrEqualTo(0.5d);
        assertThat(stats.retainedWithTree())
                .as("tree-pinning calls must stay bounded, not grow ~1:1 with detached")
                .isLessThanOrEqualTo(units);
    }

    private static File compileToClasspath(@Nonnull List<Path> sources) throws Exception {
        Path out = Files.createTempDirectory("perf-corpus-classes");
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        List<String> args = new ArrayList<>(List.of("-d", out.toString()));
        for (Path s : sources) {
            args.add(s.toAbsolutePath().toString());
        }
        int rc = compiler.run(null, null, null, args.toArray(new String[0]));
        if (rc != 0) {
            throw new IllegalStateException("corpus compilation failed rc=" + rc);
        }
        return out.toFile();
    }

    @Nonnull
    private static List<String> absolutePaths(@Nonnull List<Path> sources) {
        List<String> paths = new ArrayList<>(sources.size());
        for (Path s : sources) {
            paths.add(s.toAbsolutePath().toString());
        }
        return paths;
    }

    private static long usedHeapAfterGc(@Nonnull MemoryMXBean mem) {
        System.gc();
        try {
            Thread.sleep(50L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return mem.getHeapMemoryUsage().getUsed();
    }
}
```

Note: `report(...)` overrides `JavaInventoryRule.report(Tree, List<INode>)` which returns `List<com.ibm.rules.issue.Issue<Tree>>` (`java/src/main/java/com/ibm/plugin/rules/JavaInventoryRule.java:49`), so the import above is `com.ibm.rules.issue.Issue`. Returning `List.of()` raises no issues, so `verifyNoIssues()` passes regardless of detections.

- [ ] **Step 5: Run the perf test to verify it passes on this branch (detach live)**

Run: `mvn spotless:apply -pl java && mvn test -pl java -DexcludedGroups= -Dtest=CallStackHeapPerfTest`
Expected: PASS. Capture the printed `[callstack-perf] ...` line. Sanity-check it: `total` positive (detections fired), `detached` is the large majority, `retainedWithTree` small.

If `total == 0`: types did not resolve — verify `withClassPath(classes)` is present and the corpus compiled (the `compileToClasspath` step threw nothing). If `onFiles` rejects the absolute temp paths, generate under a module-relative dir instead (e.g. `Path root = Path.of("target", "perf-corpus");` cleaned at start) and pass module-relative paths.

- [ ] **Step 6: Tighten thresholds to the observed numbers**

Using the captured line, tighten the two assertions so they still pass comfortably on this branch but leave no room for a regression to slip through:
- Set `detachedRatio` lower bound just below the observed ratio (e.g. observed 0.98 → assert `>= 0.9`).
- Set the `retainedWithTree` bound to a small multiple of the observed value, still well under `units` and NOT proportional to `total` (e.g. observed 3 with units 100 → assert `<= 20`).

Edit the two `assertThat` bounds accordingly. Re-run Step 5's command; expected PASS.

- [ ] **Step 7: Validate the assertion discriminates (neutralize detach → must FAIL)**

This proves the test is worth committing. Temporarily make detach a no-op — comment out the body of `CallStackAgent.detachCallsForFile` (or of `JavaLanguageSupport.notifyLeaveFile`) so no call is ever swapped to its detached form:

Run: `mvn test -pl java -DexcludedGroups= -Dtest=CallStackHeapPerfTest`
Expected: **FAIL** — `retainedWithTree` now grows with the corpus (≈ `total`) and `detachedRatio` collapses toward 0, tripping both assertions. Capture the failing line to confirm.

**Revert the neutralization** (`git checkout -- engine/src/main/java/com/ibm/engine/callstack/CallStackAgent.java`) and re-run Step 5 to confirm PASS again. The neutralization is a local sanity check and is **NOT committed**.

- [ ] **Step 8: Confirm the default build still skips it, then commit**

Run: `mvn test -pl java -Dtest=CallStackHeapPerfTest` (default build)
Expected: BUILD SUCCESS, 0 tests run (tag excluded) — CI-safe.

```bash
mvn checkstyle:check -pl java
git add java/src/test/java/com/ibm/plugin/perf/CallStackHeapPerfTest.java
git commit -m "test(java): manual call-stack heap/perf harness (@Tag performance)"
```

---

## Self-Review

**Spec coverage:**
- Self-contained JUnit, no docker/network → Tasks 3–4 (generator + in-process `CheckVerifier`). ✓
- Not keycloak; synthetic corpus, scale knob → Task 3 generator, `-Dperf.corpus.files` (Task 4). ✓
- Types must resolve → Task 4 `compileToClasspath` + `withClassPath` (mirrors `CrossFileHookDetachTest`). ✓
- Wrapper/caller cross-file pattern with literal + field-constant (detachable) args → Task 3 templates. ✓ (Note: the design's `new byte[]` retained case is intentionally omitted from the generator — the primary signal is a high detach ratio + bounded tree-pinning; the retained path is already covered functionally by `CrossFileHookDetachTest`. Recorded in the spec's assertion section.)
- Structural assert (`retainedWithTree` bounded, `detachedRatio` high) via `callContextStats()` → Tasks 1–2 accessor, Task 4 asserts. ✓
- Heap/time report-only, never asserted → Task 4 `System.out.printf`, no assertion on `heapDelta`/`elapsedMs`. ✓
- Small `callContextStats()` accessor, not reflection → Tasks 1–2. ✓
- Manual only, `@Tag("performance")` + surefire `excludedGroups` → Task 4 Steps 1–3, 8. ✓
- Placement (`com.ibm.plugin.perf`, engine `callstack`/`detection`/`language`) → matches approved layout. ✓
- Harness self-validation (passes with detach, fails without) → Task 4 Step 7. ✓
- Pointer to the manual keycloak `mvn sonar:sonar` route, not automated → Task 4 test javadoc. ✓

**Placeholder scan:** No TBD/TODO. The two threshold values are concrete starting numbers (`0.5`, `units`) with an explicit, evidence-based tightening step (Task 4 Step 6) — not placeholders. All imports are exact (`Issue` verified as `com.ibm.rules.issue.Issue`).

**Type consistency:** `callContextStats()` returns `CallContextStats` at every layer (`CallStackAgent`, `Handler`, `ILanguageSupport`, `JavaLanguageSupport`). `CallContextStats.from(Collection<List<CallContext<R,T>>>)` matches `invokedCallStack.values()`'s type (`Collection<List<CallContext<R,T>>>`). `generate(Path, int) -> List<Path>` consumed consistently in Tasks 3 and 4. `detachedRatio()`, `retainedWithTree()`, `detached()`, `total()`, `buckets()` accessor names consistent between Task 1 definition and Task 4 use.
