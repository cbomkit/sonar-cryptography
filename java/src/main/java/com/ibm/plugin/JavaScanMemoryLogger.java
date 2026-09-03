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
package com.ibm.plugin;

import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;

/**
 * JVM-global Java scan memory metrics.
 *
 * <p>The Java analyzer keeps scan-level state in static plugin components, so these counters are
 * intentionally process-wide observability metrics rather than per-file or per-executive state.
 */
public final class JavaScanMemoryLogger {
    public record Snapshot(
            long javaFilesProcessed, long usedMb, long totalMb, long maxMb, long peakUsedMb) {}

    /**
     * JVM-global metric — shared across all concurrent scans in this JVM. Not safe for
     * multi-project or SonarLint daemon use without external coordination. Incremented by every
     * {@link #logFileProgress} call; zeroed by {@link #reset()}.
     *
     * <p>Note: {@link #reset()} zeroes this field and {@link #PEAK_USED_MB} in two separate
     * compare-and-set operations. A concurrent {@link #logFileProgress} call may therefore observe
     * a transiently inconsistent snapshot (one counter reset, the other not yet). This is an
     * acceptable observability trade-off for a metrics-only field.
     */
    private static final AtomicLong JAVA_FILES_PROCESSED = new AtomicLong(0);

    /**
     * JVM-global metric — shared across all concurrent scans in this JVM. Not safe for
     * multi-project or SonarLint daemon use without external coordination. Updated by every {@link
     * #logFileProgress} and {@link #snapshot} call via {@link #updatePeak(long)}; zeroed by {@link
     * #reset()}.
     *
     * <p>Note: {@link #reset()} zeroes {@link #JAVA_FILES_PROCESSED} and this field in two separate
     * compare-and-set operations. A concurrent caller may observe a partially-reset state between
     * the two assignments. This is an acceptable observability trade-off for a metrics-only field.
     */
    private static final AtomicLong PEAK_USED_MB = new AtomicLong(0);

    private JavaScanMemoryLogger() {
        // utility class
    }

    public static void logFileProgress(Logger logger, long every) {
        Runtime runtime = Runtime.getRuntime();
        long usedMb = usedMb(runtime);
        long totalMb = runtime.totalMemory() / (1024 * 1024);
        long maxMb = runtime.maxMemory() / (1024 * 1024);
        long javaFilesProcessed = JAVA_FILES_PROCESSED.incrementAndGet();
        long peakUsedMb = updatePeak(usedMb);

        if (every <= 1 || javaFilesProcessed % every == 0) {
            logger.info(
                    "CBOM memory progress: javaFiles={}, used={} MB, total={} MB, max={} MB, peak={} MB",
                    javaFilesProcessed,
                    usedMb,
                    totalMb,
                    maxMb,
                    peakUsedMb);
        }
    }

    public static Snapshot snapshot() {
        Runtime runtime = Runtime.getRuntime();
        long usedMb = usedMb(runtime);
        long javaFilesProcessed = JAVA_FILES_PROCESSED.get();
        long peakUsedMb = updatePeak(usedMb);
        return new Snapshot(
                javaFilesProcessed,
                usedMb,
                runtime.totalMemory() / (1024 * 1024),
                runtime.maxMemory() / (1024 * 1024),
                peakUsedMb);
    }

    public static void reset() {
        JAVA_FILES_PROCESSED.set(0);
        PEAK_USED_MB.set(0);
    }

    private static long usedMb(Runtime runtime) {
        return (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024);
    }

    private static long updatePeak(long usedMb) {
        return PEAK_USED_MB.updateAndGet(previousPeak -> Math.max(previousPeak, usedMb));
    }
}
