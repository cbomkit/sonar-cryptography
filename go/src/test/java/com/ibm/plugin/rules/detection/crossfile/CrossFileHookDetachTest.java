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
package com.ibm.plugin.rules.detection.crossfile;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.go.GoScanContext;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.sonar.go.symbols.Symbol;
import org.sonar.go.testing.GoVerifier;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

/**
 * Cross-file guard for the shared call-stack bucketing optimization, Go edition — documented as
 * {@code @Disabled} because it is not constructible today, for two independent reasons found while
 * auditing the {@code feat/callstack-ast-detach} branch:
 *
 * <ol>
 *   <li><b>Go registers no hooks.</b> {@code GoDetectionEngine} only ever calls {@code
 *       handler.addCallToCallStack(...)} (it populates the call stack) but never {@code
 *       addHookToHookRepository(...)} — only the Java and Python engines do. The optimization
 *       changed {@code CallStackAgent.onNewHookSubscription}/{@code bucketsToScan}, which run <em>
 *       only</em> when a hook is subscribed. With no Go hooks, that narrowed lookup path is
 *       unreachable for Go, so the change cannot drop any Go detection. Go also has no cross-scope
 *       (wrapper) argument resolution, so {@code HashIt([]byte(...))} in {@code
 *       CrossFileHookCaller.go} would not surface the MD5 inside {@code CrossFileHookWrapper.go}
 *       even within a single file.
 *   <li><b>The Go test harness is single-file.</b> {@link GoVerifier} parses exactly one source
 *       ({@code SingleFileVerifier}, one {@code parse} of {@code foo.go}); there is no two-file
 *       scan entry point to reproduce a genuine cross-file scenario.
 * </ol>
 *
 * <p>The fixtures {@code crossfile/CrossFileHookWrapper.go} and {@code
 * crossfile/CrossFileHookCaller.go} capture the intended scenario. Enable this test — and add
 * multi-file support to {@link GoVerifier} — if Go ever gains hook-based cross-scope resolution;
 * only then does the shared bucketing narrowing become reachable for Go and need this guard.
 */
class CrossFileHookDetachTest extends TestBase {

    @Disabled(
            "Go registers no hooks (bucketing path unreachable) and GoVerifier is single-file — see"
                    + " class Javadoc")
    @Test
    void crossFileHookResolvesAcrossTwoFiles() {
        // Intent (not runnable today): analyze CrossFileHookCaller.go + CrossFileHookWrapper.go in
        // one scan and assert the MD5 in the wrapper resolves at the caller. GoVerifier has no
        // multi-file entry point, so this documents the scenario rather than executing it.
        GoVerifier.verify("rules/detection/crossfile/CrossFileHookCaller.go", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<GoCheck, Tree, Symbol, GoScanContext> detectionStore,
            @Nonnull List<INode> nodes) {
        // Disabled — no findings are driven.
    }
}
