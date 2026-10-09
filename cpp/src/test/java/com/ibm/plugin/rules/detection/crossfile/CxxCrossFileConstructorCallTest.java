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
 * Constructor calls recorded while scanning {@code HasherCaller.cc} are resolved by the hook of the
 * constructor created later, while scanning {@code HasherDefinition.cc}: the calls are detached
 * when their file is left, with their arguments resolved while the file and its symbols are live,
 * an argument held by a variable as well as a braced argument.
 */
class CxxCrossFileConstructorCallTest extends TestBase {

    private static final String CALLER = "rules/detection/crossfile/HasherCaller.cc";
    private static final String DEFINITION = "rules/detection/crossfile/HasherDefinition.cc";

    private final List<String> findings = new ArrayList<>();

    @Test
    void constructorCallsOfAnEarlierFileAreResolved() {
        CxxVerifier.verifyFiles(List.of(CALLER, DEFINITION), this);

        assertThat(findings).containsExactlyInAnyOrder("SHA-224", "SHA-384");
        final CallContextStats stats = CxxAggregator.getLanguageSupport().callContextStats();
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
        nodes.forEach(node -> findings.add(node.asString()));
    }
}
