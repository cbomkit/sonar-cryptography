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

import com.ibm.plugin.bridge.ESLintBridge;
import com.ibm.plugin.bridge.ESLintExecutor;
import com.ibm.plugin.javascript.api.BlockTree;
import com.ibm.plugin.javascript.api.CallExpressionTree;
import org.junit.jupiter.api.Test;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;

class ESLintBridgeTest {

    @Test
    void analyzeFiles_extractsNodeCryptoCalls() throws Exception {
        ESLintExecutor executor = ESLintExecutor.fromClasspathResources();
        ESLintBridge bridge = new ESLintBridge(executor);

        var inputFile =
                TestInputFileBuilder.create("module", "src/crypto-example.js")
                        .setLanguage("js")
                        .setType(org.sonar.api.batch.fs.InputFile.Type.MAIN)
                        .setContents(
                                """
                                const crypto = require('crypto');
                                const hash = crypto.createHash('sha256');
                                hash.update('data');
                                """)
                        .build();

        var trees = bridge.analyzeFiles(java.util.List.of(inputFile));

        assertThat(trees).containsKey(inputFile);
        BlockTree blockTree = trees.get(inputFile);
        assertThat(blockTree.statements()).isNotEmpty();
        assertThat(blockTree.statements().stream().anyMatch(CallExpressionTree.class::isInstance))
                .isTrue();
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
    }
}
