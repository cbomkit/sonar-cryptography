/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
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
package com.ibm.engine.callstack;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.sonar.api.batch.fs.InputFile;

class DetachedScanContextTest {

    private record FakeDetachedLocation() implements DetachedLocation {}

    @Test
    void exposesFilePathAndInputFileWithoutPinningAst() {
        InputFile inputFile = mock(InputFile.class);
        DetachedScanContext<Object, Object> ctx =
                new DetachedScanContext<>(inputFile, "/abs/path/CrossFileUsage.java", null);

        assertThat(ctx.getFilePath()).isEqualTo("/abs/path/CrossFileUsage.java");
        assertThat(ctx.getInputFile()).isSameAs(inputFile);
    }

    @Test
    void reportIssueIsANoOpWhenNoReporterIsAvailable() {
        // A detached context has no live scanner context, so it cannot raise a tree-based issue; it
        // silently skips rather than failing the analysis. The CBOM node is still produced.
        DetachedScanContext<Object, Object> ctx =
                new DetachedScanContext<>(mock(InputFile.class), "/p/F.java", null);
        assertThatCode(() -> ctx.reportIssue(new Object(), new Object(), "msg"))
                .doesNotThrowAnyException();
    }

    @Test
    @SuppressWarnings("unchecked")
    void reportIssueDelegatesWhenLocationIsDetached() {
        IDetachedIssueReporter<Object, Object> reporter = mock(IDetachedIssueReporter.class);
        DetachedScanContext<Object, Object> ctx =
                new DetachedScanContext<>(mock(InputFile.class), "/p/F.java", reporter);
        Object rule = new Object();
        DetachedLocation location = new FakeDetachedLocation();

        ctx.reportIssue(rule, location, "msg");

        verify(reporter).report(rule, location, "msg");
    }

    @Test
    @SuppressWarnings("unchecked")
    void reportIssueSkipsWhenLocationIsNotDetached() {
        // T is shared with the non-detached path, so a plain Object (standing in for a live tree
        // node) reaches reportIssue here without failing to compile.
        IDetachedIssueReporter<Object, Object> reporter = mock(IDetachedIssueReporter.class);
        DetachedScanContext<Object, Object> ctx =
                new DetachedScanContext<>(mock(InputFile.class), "/p/F.java", reporter);

        assertThatCode(() -> ctx.reportIssue(new Object(), new Object(), "msg"))
                .doesNotThrowAnyException();
        verify(reporter, never()).report(any(), any(), anyString());
    }
}
