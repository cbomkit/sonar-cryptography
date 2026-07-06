# Call-stack Heap Attribution (H1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Attribute the post-detach heap floor (observed ~1.6 → ~3.4 GB over a scan) to its actual sources — retained CBOM `INode`s vs. detached call-stack records vs. hooks — so a written decision can gate the deferred call-stack trim (H2).

**Architecture:** Purely additive observability. A small immutable summary record composes the three population *counts* already reachable in-process; `OutputFileJob` logs it once at end-of-scan; the perf harness prints the CBOM-node count alongside its existing `CallContextStats` line. True *byte* attribution is a documented manual `jmap -histo:live` runbook on a constrained-heap Keycloak scan. No engine API changes, no detection-behavior changes.

**Tech Stack:** Java 17, Maven multi-module, SLF4J, JUnit 5 + AssertJ, SonarQube PostJob API, `jmap`.

## Global Constraints

- Java 17; changes confined to `sonar-cryptography-plugin` (main + test), `java` test/perf, and `docs/`. No `engine` or language-support API changes in H1.
- Apache 2.0 license header in every new `.java` file — copy verbatim from a neighbor (e.g. `sonar-cryptography-plugin/src/main/java/com/ibm/plugin/OutputFileJob.java` lines 1–19), updating the year to 2026 for new files.
- Run `mvn spotless:apply` before every commit. If Spotless truncates `JsonCipherSuites`, restore it before committing (known issue).
- `mvn test -pl sonar-cryptography-plugin` and `mvn test -pl java` stay green throughout.
- H2 (eligibility filter + retention cap) is explicitly **out of scope** — this plan ends with the attribution decision that decides whether/how H2 proceeds. Do not add the filter or cap here.

## Scope Check

This is a single, self-contained observability + measurement deliverable (one subsystem: end-of-scan reporting). It does not need decomposition.

## File Structure

```
sonar-cryptography-plugin/src/main/java/com/ibm/plugin/
  HeapAttributionSummary.java   (CREATE)  immutable record of the three population counts + a format() string
  OutputFileJob.java            (MODIFY)  build the summary and DEBUG-log it once, before reset()
  ScannerManager.java           (MODIFY)  heapAttribution() — read the counts from the aggregators/lang-support
sonar-cryptography-plugin/src/test/java/com/ibm/plugin/
  HeapAttributionSummaryTest.java (CREATE) unit test for the record + format()
  ScannerManagerTest.java         (CREATE) test heapAttribution() reflects added nodes
java/src/test/java/com/ibm/plugin/perf/
  CallStackHeapPerfTest.java    (MODIFY)  add detectedNodes count to the printed report line
docs/
  PERFORMANCE_TESTING.md        (MODIFY)  jmap attribution runbook + results-table template + decision rule
```

**Responsibilities:**
- `HeapAttributionSummary` — pure value + formatting; the single testable unit, no statics.
- `ScannerManager.heapAttribution()` — the one place that reads the static aggregators / language support and constructs the summary.
- `OutputFileJob` — end-of-scan trigger; logs the summary.
- `CallStackHeapPerfTest` — fast in-process signal for local iteration.
- `PERFORMANCE_TESTING.md` — the decisive manual byte-attribution procedure + where the H1 decision is recorded.

---

## Task 1: `HeapAttributionSummary` record + `format()`

**Files:**
- Create: `sonar-cryptography-plugin/src/main/java/com/ibm/plugin/HeapAttributionSummary.java`
- Test: `sonar-cryptography-plugin/src/test/java/com/ibm/plugin/HeapAttributionSummaryTest.java`

**Interfaces:**
- Consumes: nothing.
- Produces: `record HeapAttributionSummary(int detectedNodes, int detachedCalls, int totalCalls, int callStackBuckets)` with instance method `String format()`.

- [ ] **Step 1: Write the failing test**

Create `sonar-cryptography-plugin/src/test/java/com/ibm/plugin/HeapAttributionSummaryTest.java` (copy the license header from `OutputFileJob.java`, year 2026):

```java
package com.ibm.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class HeapAttributionSummaryTest {

    @Test
    void formatContainsAllFourPopulationCounts() {
        HeapAttributionSummary summary = new HeapAttributionSummary(1200, 179000, 630000, 15800);
        String line = summary.format();
        assertThat(line)
                .contains("detectedNodes=1200")
                .contains("detachedCalls=179000")
                .contains("totalCalls=630000")
                .contains("callStackBuckets=15800");
    }

    @Test
    void formatIsStableForZeroPopulations() {
        assertThat(new HeapAttributionSummary(0, 0, 0, 0).format())
                .isEqualTo(
                        "[heap-attribution] detectedNodes=0 detachedCalls=0 "
                                + "totalCalls=0 callStackBuckets=0");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl sonar-cryptography-plugin -Dtest=HeapAttributionSummaryTest`
Expected: FAIL — `HeapAttributionSummary` does not exist (compilation error).

- [ ] **Step 3: Write minimal implementation**

Create `sonar-cryptography-plugin/src/main/java/com/ibm/plugin/HeapAttributionSummary.java` (license header from `OutputFileJob.java`, year 2026):

```java
package com.ibm.plugin;

import javax.annotation.Nonnull;

/**
 * End-of-scan snapshot of the three heap populations whose relative size decides the H1
 * attribution: retained CBOM nodes, detached call-stack records, and the call-stack bucket count.
 * Counts only — byte attribution is the manual {@code jmap} runbook in {@code
 * docs/PERFORMANCE_TESTING.md}.
 *
 * @param detectedNodes retained CBOM {@code INode}s (Java aggregator)
 * @param detachedCalls tree-free {@code DetachedCall}s in the call stack
 * @param totalCalls total recorded calls (detached + retained-with-tree)
 * @param callStackBuckets number of hash buckets in the call stack
 */
public record HeapAttributionSummary(
        int detectedNodes, int detachedCalls, int totalCalls, int callStackBuckets) {

    @Nonnull
    public String format() {
        return "[heap-attribution] detectedNodes="
                + detectedNodes
                + " detachedCalls="
                + detachedCalls
                + " totalCalls="
                + totalCalls
                + " callStackBuckets="
                + callStackBuckets;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn test -pl sonar-cryptography-plugin -Dtest=HeapAttributionSummaryTest`
Expected: PASS (2 tests).

- [ ] **Step 5: Format and commit**

```bash
mvn spotless:apply -pl sonar-cryptography-plugin
git add sonar-cryptography-plugin/src/main/java/com/ibm/plugin/HeapAttributionSummary.java \
        sonar-cryptography-plugin/src/test/java/com/ibm/plugin/HeapAttributionSummaryTest.java
git commit -m "feat(plugin): heap-attribution summary record for scan-floor analysis"
```

---

## Task 2: `ScannerManager.heapAttribution()` + end-of-scan log

**Files:**
- Modify: `sonar-cryptography-plugin/src/main/java/com/ibm/plugin/ScannerManager.java`
- Modify: `sonar-cryptography-plugin/src/main/java/com/ibm/plugin/OutputFileJob.java:39-55`
- Test: `sonar-cryptography-plugin/src/test/java/com/ibm/plugin/ScannerManagerTest.java`

**Interfaces:**
- Consumes: `HeapAttributionSummary(int, int, int, int)` from Task 1; `JavaAggregator.getDetectedNodes()`, `JavaAggregator.getLanguageSupport().callContextStats()` (returns `com.ibm.engine.callstack.CallContextStats` with `detached()`, `total()`, `buckets()`), `JavaAggregator.addNodes(List<INode>)`, `JavaAggregator.reset()`.
- Produces: `ScannerManager.heapAttribution()` returning `HeapAttributionSummary`.

- [ ] **Step 1: Write the failing test**

Create `sonar-cryptography-plugin/src/test/java/com/ibm/plugin/ScannerManagerTest.java` (license header from `OutputFileJob.java`, year 2026):

```java
package com.ibm.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ScannerManagerTest {

    @BeforeEach
    @AfterEach
    void clearAggregators() {
        JavaAggregator.reset();
    }

    @Test
    void heapAttributionReportsZeroPopulationsOnAFreshScanner() {
        HeapAttributionSummary summary = new ScannerManager(null).heapAttribution();
        assertThat(summary.detectedNodes()).isZero();
        assertThat(summary.totalCalls()).isZero();
        assertThat(summary.callStackBuckets()).isZero();
    }

    @Test
    void heapAttributionCountsRetainedDetectedNodes() {
        DetectionLocation location =
                new DetectionLocation("Test.java", 1, 0, List.of("aes"), () -> "test");
        JavaAggregator.addNodes(List.<INode>of(new AES(128, location)));

        HeapAttributionSummary summary = new ScannerManager(null).heapAttribution();
        assertThat(summary.detectedNodes()).isEqualTo(1);
    }
}
```

Note: `new AES(int keyLength, DetectionLocation)` and the `DetectionLocation(String, int, int, List<String>, IBundle)` record are verified real; `IBundle` is a functional interface, so `() -> "test"` supplies it (matching the `mapper` module's own test fixtures). The assertion (`detectedNodes() == 1`) is what matters, not which node type.

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -pl sonar-cryptography-plugin -Dtest=ScannerManagerTest`
Expected: FAIL — `ScannerManager.heapAttribution()` does not exist (compilation error).

- [ ] **Step 3: Add `heapAttribution()` to `ScannerManager`**

In `ScannerManager.java`, add these imports near the existing ones:

```java
import com.ibm.engine.callstack.CallContextStats;
```

Add this method after `getAggregatedNodes()` (around line 70):

```java
    /**
     * Snapshot of the heap populations whose relative size attributes the post-detach scan-floor
     * growth: retained CBOM nodes vs. detached call-stack records (see the H1 attribution in {@code
     * docs/PERFORMANCE_TESTING.md}). Java is the measured heap driver; Python/Go call stacks are
     * not included.
     */
    @Nonnull
    public HeapAttributionSummary heapAttribution() {
        int detectedNodes = JavaAggregator.getDetectedNodes().size();
        CallContextStats stats = JavaAggregator.getLanguageSupport().callContextStats();
        return new HeapAttributionSummary(
                detectedNodes, stats.detached(), stats.total(), stats.buckets());
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn test -pl sonar-cryptography-plugin -Dtest=ScannerManagerTest`
Expected: PASS (2 tests).

- [ ] **Step 5: Wire the log into `OutputFileJob`**

In `OutputFileJob.java`, replace the body of `execute` (lines 39–55) so the attribution logs once, before `reset()`, regardless of whether results exist:

```java
    @Override
    public void execute(PostJobContext postJobContext) {
        final String cbomFilename =
                postJobContext
                        .config()
                        .get(Constants.CBOM_OUTPUT_NAME)
                        .orElse(Constants.CBOM_OUTPUT_NAME_DEFAULT);
        ScannerManager scannerManager = new ScannerManager(new CBOMOutputFileFactory());
        if (scannerManager.hasResults()) {
            final File cbom = new File(cbomFilename + ".json");
            scannerManager.getOutputFile().saveTo(cbom);
            LOGGER.info("CBOM was successfully generated '{}'.", cbom.getAbsolutePath());
            scannerManager.getStatistics().print(LOGGER::info);
        } else {
            LOGGER.info("No cryptography assets were detected. CBOM will not be generated.");
        }
        LOGGER.debug(scannerManager.heapAttribution().format());
        scannerManager.reset();
    }
```

- [ ] **Step 6: Run the plugin module tests**

Run: `mvn test -pl sonar-cryptography-plugin`
Expected: PASS (existing `OutputFileJobTest`, `PluginTest`, `JavaFileCheckRegistrarTest` plus the two new tests).

- [ ] **Step 7: Format and commit**

```bash
mvn spotless:apply -pl sonar-cryptography-plugin
git add sonar-cryptography-plugin/src/main/java/com/ibm/plugin/ScannerManager.java \
        sonar-cryptography-plugin/src/main/java/com/ibm/plugin/OutputFileJob.java \
        sonar-cryptography-plugin/src/test/java/com/ibm/plugin/ScannerManagerTest.java
git commit -m "feat(plugin): log heap-attribution populations at end of scan"
```

---

## Task 3: Add CBOM-node count to the perf harness report line

**Files:**
- Modify: `java/src/test/java/com/ibm/plugin/perf/CallStackHeapPerfTest.java:103-118`

**Interfaces:**
- Consumes: `JavaAggregator.getDetectedNodes()` (already imported in this test), the existing `CallContextStats stats` local.
- Produces: nothing (test-only reporting).

- [ ] **Step 1: Add the detectedNodes count to the printed report**

In `CallStackHeapPerfTest.detachesRecordedCallsAtScale`, the report block currently prints `retainedWithTree/detached/total/buckets/ratio`. Add the retained CBOM-node count so the harness shows both heap populations side by side. Replace the `System.out.printf(...)` call (lines 106–117) with:

```java
        System.out.printf(
                "%n[callstack-perf] files=%d units=%d time=%dms heapDeltaMB=%d "
                        + "detectedNodes=%d "
                        + "retainedWithTree=%d detached=%d total=%d buckets=%d ratio=%.3f%n",
                sources.size(),
                units,
                elapsedMs,
                (heapAfter - heapBefore) / (1024L * 1024L),
                JavaAggregator.getDetectedNodes().size(),
                stats.retainedWithTree(),
                stats.detached(),
                stats.total(),
                stats.buckets(),
                stats.detachedRatio());
```

(No new import — `com.ibm.plugin.JavaAggregator` is already imported at line 27.)

- [ ] **Step 2: Run the perf harness and eyeball the new field**

Run: `mvn test -pl java -DexcludedGroups= -Dtest=CallStackHeapPerfTest`
Expected: PASS; the printed line now includes `detectedNodes=<n>`. Note it reads `detectedNodes=0`
in this harness — the `CheckVerifier`/`TestBase` path constructs rules with `isInventory=false`
(`JavaBaseDetectionRule.java:52`), so `JavaAggregator.addNodes` never fires here; the count is
non-zero only on a real inventory scan (Keycloak). The existing assertions (`total()` positive,
`detachedRatio >= 0.9`, `retainedWithTree <= 10`) still hold.

- [ ] **Step 3: Commit**

```bash
git add java/src/test/java/com/ibm/plugin/perf/CallStackHeapPerfTest.java
git commit -m "test(java): report detectedNodes count in call-stack perf harness"
```

---

## Task 4: Byte-attribution runbook + decision in `PERFORMANCE_TESTING.md`

**Files:**
- Modify: `docs/PERFORMANCE_TESTING.md`

**Interfaces:** none (documentation).

- [ ] **Step 1: Append the attribution section**

Add a new top-level section to `docs/PERFORMANCE_TESTING.md` (after the existing Keycloak end-to-end section). Paste it verbatim:

````markdown
---

## C. Post-detach floor attribution (H1)

AST-detach removed the dominant AST-pinning heap term, but the post-GC floor still grows over a
scan (observed ~1.6 → ~3.4 GB). This procedure attributes that residual to one of three
populations so we know whether the call-stack still needs trimming (H2) or whether retained CBOM
nodes dominate (a separate follow-up).

### Two signals

**1. In-process population counts (cheap).** At end of scan the plugin logs, at DEBUG:

```
[heap-attribution] detectedNodes=<n> detachedCalls=<n> totalCalls=<n> callStackBuckets=<n>
```

Enable DEBUG for the plugin (e.g. `-Dsonar.log.level=DEBUG` on the scanner, or the analysis
`sonar.verbose=true`) and read the line from the scanner log. The fast local proxy is
`CallStackHeapPerfTest`, whose report line now also prints `detectedNodes=<n>`.

Counts size the *populations*, not their bytes — a small count of heavy objects can still
dominate. Use them to spot which population grows, then confirm bytes with the histogram below.

**2. Byte attribution via `jmap` (decisive).** During a constrained-heap Keycloak scan (see
section B), capture a live histogram near the end of analysis:

```bash
# find the scanner JVM pid (the surefire/scanner java process running the analysis)
jps -l
# live histogram (forces a GC first), sorted by retained bytes
jmap -histo:live <pid> > histo.txt
```

Bucket the top entries of `histo.txt` into the three sources:

| Bucket | Classes to sum in `histo.txt` |
|---|---|
| Retained CBOM nodes | `com.ibm.mapper.model.**` (e.g. `Algorithm`, `Key`, `Property`, `MessageDigest`, …) and their child `HashMap`/`HashMap$Node` share |
| Detached call-stack | `com.ibm.engine.callstack.DetachedCall`, `...callstack.ArgSnapshot`, `...callstack.ResolvedSnapshotValue` |
| Residual Tree / hooks | `org.sonar.**Tree*` still live + `com.ibm.engine.hooks.**` |

Sample two or three histograms as the scan progresses to see which bucket *grows* (the floor is
about accumulation, not a one-time cost).

### Decision (fill in after measuring)

| Population | count (log) | approx. retained bytes (jmap) |
|---|---|---|
| Retained CBOM nodes | | |
| Detached call-stack | | |
| Residual Tree / hooks | | |

Record the outcome here, then route H2 accordingly:

- **Call-stack dominates** → proceed with H2: eligibility filter **and** retention cap.
- **CBOM nodes dominate** → build only H2's eligibility filter (still a lossless trim + CPU
  assist); open a separate spec for `detectedNodes` dedup / incremental emission.
- **Hooks dominate** → open a hooks-subscription-pruning spec.

> Note on H2's eligibility filter: the predicate cannot be derived from `methodSymbol().declaration()`
> — cross-file *user* calls resolve via `sonar.java.binaries` and have a null declaration, exactly
> like library calls (see the comment in `JavaLanguageSupport.isDetachableCall`). The discriminator
> must be pinned empirically against the `crossfile/` fixtures before the filter is written.
````

- [ ] **Step 2: Commit**

```bash
git add docs/PERFORMANCE_TESTING.md
git commit -m "docs: post-detach floor attribution runbook (H1) + H2 decision rule"
```

---

## Task 5: Full-suite regression + measurement run

**Files:** none (verification).

- [ ] **Step 1: Run the two touched module suites**

Run: `mvn test -pl sonar-cryptography-plugin && mvn test -pl java`
Expected: both green (the `java` default run excludes `@Tag("performance")`, so `CallStackHeapPerfTest` does not run here).

- [ ] **Step 2: Capture the in-process signal**

Run: `mvn test -pl java -DexcludedGroups= -Dtest=CallStackHeapPerfTest`
Expected: report line prints `detectedNodes=<n>` and `detached=<n>`; note both.

- [ ] **Step 3: Run the decisive measurement**

Follow `docs/PERFORMANCE_TESTING.md` section C on a Keycloak scan: read the `[heap-attribution]`
DEBUG line and capture at least two `jmap -histo:live` snapshots. Fill in the decision table and
write the one-paragraph outcome + H2 routing in the doc.

- [ ] **Step 4: Commit the recorded decision**

```bash
git add docs/PERFORMANCE_TESTING.md
git commit -m "docs: record H1 floor-attribution results and H2 routing decision"
```

---

## Self-Review notes

- **Spec coverage:** H1's two signals (in-process counts + jmap byte attribution) → Tasks 1–4; the written decision + routing → Task 4 template and Task 5. H2 filter/cap deliberately excluded per the H1-only scope decision; the doc note preserves the corrected-predicate finding so H2 isn't rebuilt on the wrong premise.
- **No placeholders:** the only unfilled content is the runtime measurement table (Task 4/5), which is inherent to a measurement deliverable — the *procedure*, commands, and jmap class buckets are fully concrete.
- **Type consistency:** `HeapAttributionSummary(int detectedNodes, int detachedCalls, int totalCalls, int callStackBuckets)` is used identically in Tasks 1–2; `CallContextStats.detached()/total()/buckets()` match the record defined in `engine/.../callstack/CallContextStats.java`.
