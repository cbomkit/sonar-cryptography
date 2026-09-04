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
package com.ibm.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.Finding;
import com.ibm.engine.executive.DetectionExecutive;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.plugin.bridge.ESLintBridge;
import com.ibm.plugin.bridge.ESLintExecutor;
import com.ibm.plugin.javascript.api.BlockTree;
import com.ibm.plugin.javascript.api.CallExpressionTree;
import com.ibm.plugin.javascript.api.JavaScriptCheck;
import com.ibm.plugin.javascript.api.JavaScriptSymbol;
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.javascript.language.JavaScriptLanguageSupport;
import com.ibm.plugin.javascript.language.JavaScriptScanContext;
import com.ibm.plugin.rules.detection.nodecrypto.NodeCryptoHash;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;

class JavaScriptDetectionIntegrationTest {

    @BeforeEach
    void setUp() {
        JavaScriptAggregator.reset();
    }

    @Test
    void createHashRuleMatchesAndEmitsFinding() throws Exception {
        var inputFile =
                TestInputFileBuilder.create("test-module", "NodeCryptoHashTestFile.js")
                        .setLanguage("js")
                        .setType(org.sonar.api.batch.fs.InputFile.Type.MAIN)
                        .setContents(
                                """
                                const crypto = require('crypto');
                                const hash = crypto.createHash('md5');
                                hash.update('hello');
                                const digest = hash.digest('hex');
                                """)
                        .build();

        ESLintBridge bridge = new ESLintBridge(ESLintExecutor.fromClasspathResources());
        BlockTree blockTree = bridge.analyzeFiles(List.of(inputFile)).get(inputFile);
        assertThat(blockTree).isNotNull();

        CallExpressionTree createHash =
                blockTree.statements().stream()
                        .flatMap(
                                tree ->
                                        tree
                                                        instanceof
                                                        com.ibm.plugin.javascript.api
                                                                        .CallExpressionWithBlockTree
                                                                wrapped
                                                ? java.util.stream.Stream.of(wrapped.call())
                                                : tree instanceof CallExpressionTree call
                                                        ? java.util.stream.Stream.of(call)
                                                        : java.util.stream.Stream.empty())
                        .filter(call -> "createHash".equals(call.methodName()))
                        .findFirst()
                        .orElseThrow();

        assertThat(createHash.objectType()).isEqualTo("crypto");

        var translation = new JavaScriptLanguageSupport().translation();
        IDetectionRule<Tree> rule = NodeCryptoHash.rules().get(0);
        assertThat(rule.match(createHash, translation)).isTrue();

        List<Finding<JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext>> findings =
                new ArrayList<>();
        JavaScriptScanContext scanContext =
                new JavaScriptScanContext(inputFile, (file, line, column, message) -> {});
        DetectionExecutive<JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext> exec =
                JavaScriptAggregator.getLanguageSupport()
                        .createDetectionExecutive(blockTree, rule, scanContext);
        exec.subscribe(finding -> findings.add(finding));
        exec.start();

        assertThat(findings).isNotEmpty();
    }
}
