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
 * A call recorded, and detached, while scanning {@code NamespaceCaller.cc}, of a function of the
 * namespace it is in named without its namespace, is resolved by the hook of {@code util::digest}
 * created later, while scanning {@code NamespaceDefinition.cc}: the detached call keeps the names
 * C++ name lookup tries for it.
 */
class CxxCrossFileNamespaceCallTest extends TestBase {

    private static final String CALLER = "rules/detection/crossfile/NamespaceCaller.cc";
    private static final String DEFINITION = "rules/detection/crossfile/NamespaceDefinition.cc";

    private final List<String> findings = new ArrayList<>();

    @Test
    void aCallOfAnEarlierFileInTheNamespaceIsResolved() {
        CxxVerifier.verifyFiles(List.of(CALLER, DEFINITION), this);

        assertThat(findings).containsExactly("SHA-512/256");
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
