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
import com.ibm.plugin.CxxAggregator;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.nio.file.Path;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * Manual heap/perf harness for the cxx call-stack AST-detach mechanism - the cpp analogue of {@code
 * com.ibm.plugin.perf.CallStackHeapPerfTest} in the java module. Generates a synthetic corpus of
 * OpenSSL {@code EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), ...)}-shaped call sites (scale via
 * {@code -Dperf.corpus.files}, default 200) - the nested-call-argument shape that used to make
 * {@code CxxLanguageTranslation#createTypeFromCxxType} close over a live sonar-cxx {@code Type}
 * (and, through its {@code TypeSymbol}'s {@code declaration()}, the whole file's AST), silently
 * defeating the AST-detach mechanism - scans it in-process via {@link
 * CxxVerifier#verifyAbsoluteFiles} (the corpus lives in a JUnit {@code @TempDir}, outside {@code
 * src/test/files/}, so the relative-path {@link CxxVerifier#verifyFiles} does not apply), then
 * asserts the recorded calls stayed detached (ASTs released) at {@code leaveFile}. Heap delta and
 * wall-time are printed for manual comparison, never asserted.
 *
 * <p>Excluded from the default build via {@code @Tag("performance")}. Run with: {@code mvn test -pl
 * cpp -DexcludedGroups= -Dtest=CxxCallStackHeapPerfTest} (add {@code -Dperf.corpus.files=3000} for
 * a heavy soak).
 */
@Tag("performance")
class CxxCallStackHeapPerfTest extends TestBase {

    private static final int FILES = Integer.getInteger("perf.corpus.files", 200);

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        // no per-finding assertions; the harness asserts on aggregate CallContextStats below
    }

    @Test
    void detachesRecordedCallsAtScale(@TempDir Path tmp) throws Exception {
        List<Path> sources = CxxCryptoCorpusGenerator.generate(tmp, FILES);

        MemoryMXBean mem = ManagementFactory.getMemoryMXBean();
        long heapBefore = usedHeapAfterGc(mem);
        long start = System.nanoTime();

        CxxVerifier.verifyAbsoluteFiles(sources, this);

        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;
        long heapAfter = usedHeapAfterGc(mem);

        CallContextStats stats = CxxAggregator.getLanguageSupport().callContextStats();

        // REPORT (never asserted)
        System.out.printf(
                "%n[cxx-callstack-perf] files=%d time=%dms heapDeltaMB=%d detectedNodes=%d "
                        + "retainedWithTree=%d detached=%d total=%d buckets=%d ratio=%.3f%n",
                sources.size(),
                elapsedMs,
                (heapAfter - heapBefore) / (1024L * 1024L),
                CxxAggregator.getDetectedNodes().size(),
                stats.retainedWithTree(),
                stats.detached(),
                stats.total(),
                stats.buckets(),
                stats.detachedRatio());

        // ASSERT (deterministic gate - object-variant counts, no heap/time dependence)
        assertThat(stats.total())
                .as("detections must fire (compiled classpath) or the harness proves nothing")
                .isPositive();
        assertThat(stats.detachedRatio())
                .as("most recorded calls must be detached (ASTs released at leaveFile)")
                .isGreaterThanOrEqualTo(0.9d);
        assertThat(stats.retainedWithTree())
                .as(
                        "tree-pinning calls must stay bounded, not grow ~1:1 with detached - "
                                + "regresses if createTypeFromCxxType (or any IType factory) ever "
                                + "captures a live cxx Type/AstNode again")
                .isLessThanOrEqualTo(10);
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
