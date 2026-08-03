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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.callstack.CallContextStats;
import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.CxxAggregator;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * First true cross-file detection test in the cpp suite: a hook created while scanning {@code
 * CipherFetchWrapper.cc} resolves calls recorded while scanning {@code CipherFetchCaller.cc}, in
 * one shared scan (via {@link CxxVerifier#verifyFiles}).
 *
 * <p>Unlike the Java/Python analogues, cxx's {@code CxxSymbolResolverVisitor} scopes its symbol
 * table per file ({@code leaveFile} pops it), so {@code make_cipher}'s call in the caller does not
 * symbolically link to its definition in the wrapper. Cross-file resolution here instead relies
 * purely on the method-name-hash bucketing in {@code CallStackAgent} (see {@code
 * CxxLanguageTranslation#getMethodName}, which is syntactic, not symbol-resolution-based): the hook
 * registered against {@code "make_cipher"} while analyzing the wrapper's {@code
 * EVP_CIPHER_fetch(lib, alg, props)} call (where {@code alg} is an unresolved parameter, forcing
 * {@code CxxDetectionEngine#resolveValuesInOuterScope}) matches the recorded {@code
 * make_cipher(...)} calls from the caller file purely by name.
 *
 * <p>This guards the AST-detach work end-to-end: both calls in the caller pass a
 * record-time-resolvable argument (a string literal, a global constant), so both are detachable —
 * asserted both via the resolved CBOM values (proving cross-file matching still works after detach)
 * and via {@link CallContextStats} (proving the detach actually happened, i.e. {@code leaveFile}
 * released the just-scanned file's retained calls).
 */
class CxxCrossFileHookDetachTest extends TestBase {

    private static final String WRAPPER = "rules/detection/crossfile/CipherFetchWrapper.cc";
    private static final String CALLER = "rules/detection/crossfile/CipherFetchCaller.cc";

    private static final List<String> resolvedValues = new ArrayList<>();

    @Test
    void crossFileDetectionAcrossDetachedCalls() {
        resolvedValues.clear();

        CxxVerifier.verifyFiles(List.of(WRAPPER, CALLER), this);

        // Both the literal and global-constant arguments resolve cross-file into the CBOM:
        assertThat(resolvedValues).contains("AES-128-SIV", "AES-192-SIV");

        // The detach mechanism actually ran: both calls recorded while scanning the wrapper and
        // caller files were swapped for their tree-free detached form once each file's leaveFile
        // fired, not left pinning their AST.
        CallContextStats stats = CxxAggregator.getLanguageSupport().callContextStats();
        assertThat(stats.total()).as("calls must have been recorded for this scan").isPositive();
        assertThat(stats.detached())
                .as("cross-file-resolved calls must be detached, not retained")
                .isPositive();
        assertThat(stats.retainedWithTree())
                .as("no call should still be pinning a live AST after both files' leaveFile ran")
                .isZero();
    }

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
        collectAlgorithmValues(detectionStore);
    }

    private void collectAlgorithmValues(
            @Nonnull
                    DetectionStore<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            store) {
        for (IValue<AstNode> value : store.getDetectionValues()) {
            resolvedValues.add(value.asString());
        }
        store.getChildren().forEach(this::collectAlgorithmValues);
    }
}
