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
 * cross-file crypto corpus (scale via {@code -Dperf.corpus.files}, default 200), scans it
 * in-process through {@link CheckVerifier} (compiled to a classpath dir so callee types resolve and
 * cross-file detections fire), then asserts the recorded calls were detached (ASTs released) at
 * {@code leaveFile}. Heap delta and wall-time are printed for manual comparison, never asserted.
 *
 * <p>Excluded from the default build via {@code @Tag("performance")}. Run with: {@code mvn test -pl
 * java -DexcludedGroups= -Dtest=CallStackHeapPerfTest} (add {@code -Dperf.corpus.files=3000} for a
 * heavy soak). This does NOT reproduce the full-project ~7 GB keycloak number — that remains the
 * documented manual {@code mvn sonar:sonar} route in {@code
 * docs/superpowers/plans/2026-07-05-callstack-hooks-heap-reduction.md}.
 */
@Tag("performance")
class CallStackHeapPerfTest extends TestBase {

    private static final int FILES = Integer.getInteger("perf.corpus.files", 200);

    /**
     * Raise no SonarQube issues, so the harness is decoupled from {@code // Noncompliant} lines.
     */
    @Override
    public List<Issue<Tree>> report(
            @Nonnull Tree markerTree, @Nonnull List<INode> translatedNodes) {
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

        // ASSERT (deterministic gate — object-variant counts, no heap/time dependence)
        assertThat(stats.total())
                .as("detections must fire (compiled classpath) or the harness proves nothing")
                .isPositive();
        // Observed on feat/callstack-ast-detach (200 files): ratio=1.000, retainedWithTree=0.
        // With detach disabled these collapse to ratio~0 and retainedWithTree~total, so the
        // margins below stay comfortably true here yet fail hard on any regression.
        assertThat(stats.detachedRatio())
                .as("most recorded calls must be detached (ASTs released at leaveFile)")
                .isGreaterThanOrEqualTo(0.9d);
        assertThat(stats.retainedWithTree())
                .as("tree-pinning calls must stay bounded, not grow ~1:1 with detached")
                .isLessThanOrEqualTo(10);
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
