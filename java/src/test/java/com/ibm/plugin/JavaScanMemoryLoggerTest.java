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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

class JavaScanMemoryLoggerTest {

    private Logger logger;

    @BeforeEach
    void setUp() {
        logger = mock(Logger.class);
        JavaScanMemoryLogger.reset();
    }

    @Test
    void logFileProgress_incrementsJavaFilesProcessed() {
        JavaScanMemoryLogger.logFileProgress(logger, 1);
        JavaScanMemoryLogger.logFileProgress(logger, 1);

        assertThat(JavaScanMemoryLogger.snapshot().javaFilesProcessed()).isEqualTo(2);
    }

    @Test
    void logFileProgress_logsEveryFile_whenEveryIsOne() {
        JavaScanMemoryLogger.logFileProgress(logger, 1);
        JavaScanMemoryLogger.logFileProgress(logger, 1);
        JavaScanMemoryLogger.logFileProgress(logger, 1);

        verify(logger, times(3)).info(anyString(), any(), any(), any(), any(), any());
    }

    @Test
    void logFileProgress_throttlesLogging_whenEveryIsGreaterThanOne() {
        // With every=3, only the 3rd call should log
        JavaScanMemoryLogger.logFileProgress(logger, 3);
        JavaScanMemoryLogger.logFileProgress(logger, 3);
        JavaScanMemoryLogger.logFileProgress(logger, 3);

        verify(logger, times(1)).info(anyString(), any(), any(), any(), any(), any());
    }

    @Test
    void logFileProgress_doesNotLog_whenCountDoesNotMatchInterval() {
        // With every=5, calls 1 and 2 should not log
        JavaScanMemoryLogger.logFileProgress(logger, 5);
        JavaScanMemoryLogger.logFileProgress(logger, 5);

        verify(logger, never()).info(anyString(), any(), any(), any(), any(), any());
    }

    @Test
    void snapshot_returnsNonNegativeMemoryValues() {
        JavaScanMemoryLogger.Snapshot snapshot = JavaScanMemoryLogger.snapshot();

        assertThat(snapshot.usedMb()).isGreaterThanOrEqualTo(0);
        assertThat(snapshot.totalMb()).isGreaterThan(0);
        assertThat(snapshot.maxMb()).isGreaterThan(0);
        assertThat(snapshot.peakUsedMb()).isGreaterThanOrEqualTo(0);
    }

    @Test
    void snapshot_javaFilesProcessed_reflectsLogProgressCalls() {
        JavaScanMemoryLogger.logFileProgress(logger, 1);
        JavaScanMemoryLogger.logFileProgress(logger, 1);
        JavaScanMemoryLogger.logFileProgress(logger, 1);

        assertThat(JavaScanMemoryLogger.snapshot().javaFilesProcessed()).isEqualTo(3);
    }

    @Test
    void snapshot_peakUsedMb_isAtLeastCurrentUsedMb() {
        JavaScanMemoryLogger.logFileProgress(logger, 1);
        JavaScanMemoryLogger.Snapshot snapshot = JavaScanMemoryLogger.snapshot();

        assertThat(snapshot.peakUsedMb()).isGreaterThanOrEqualTo(snapshot.usedMb());
    }

    @Test
    void reset_clearsAllCounters() {
        JavaScanMemoryLogger.logFileProgress(logger, 1);
        JavaScanMemoryLogger.logFileProgress(logger, 1);

        JavaScanMemoryLogger.reset();
        JavaScanMemoryLogger.Snapshot snapshot = JavaScanMemoryLogger.snapshot();

        // File counters are cleared to zero by reset()
        assertThat(snapshot.javaFilesProcessed()).isZero();
        assertThat(snapshot.successfulFileStateResets()).isZero();
        // peakUsedMb is not checked here: snapshot() re-samples live JVM memory and
        // immediately updates the peak, so it cannot be zero after a reset() + snapshot() call.
    }

    @Test
    void reset_isIdempotent() {
        JavaScanMemoryLogger.logFileProgress(logger, 1);

        JavaScanMemoryLogger.reset();
        JavaScanMemoryLogger.reset();

        assertThat(JavaScanMemoryLogger.snapshot().javaFilesProcessed()).isZero();
    }
}
