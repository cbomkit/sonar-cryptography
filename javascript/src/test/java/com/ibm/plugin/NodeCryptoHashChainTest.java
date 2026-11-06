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

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.javascript.language.JavaScriptCheck;
import com.ibm.plugin.javascript.language.JavaScriptScanContext;
import com.ibm.plugin.javascript.language.JavaScriptSymbol;
import com.ibm.plugin.javascript.tree.JavaScriptTree;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Feasibility test for the ANTLR-based JavaScript/TypeScript pipeline.
 *
 * <p>A typed TypeScript fixture holds the same {@code createHash} / {@code update} / {@code digest}
 * operation twice, as separate statements and as one inline chain. Each form must give exactly one
 * finding with the algorithm resolved, the dependent {@code update} and {@code digest} rules
 * attached to it, and a digest node in the CBOM translation. This is the path the previous
 * ESLint-based attempt could not follow, because its tree attached an empty block to each call.
 */
class NodeCryptoHashChainTest extends TestBase {

    @Test
    void test() throws Exception {
        JavaScriptVerifier.verify("rules/detection/NodeCryptoHashTestFile.ts", this);
        assertThat(findingCount()).as("one finding per createHash call").isEqualTo(3);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<
                                    JavaScriptCheck,
                                    JavaScriptTree,
                                    JavaScriptSymbol,
                                    JavaScriptScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        final String expectedAlgorithm;
        final String expectedNode;
        switch (findingId) {
            case 0 -> { // const hash = crypto.createHash('sha256'); hash.update(..);
                // hash.digest(..)
                expectedAlgorithm = "sha256";
                expectedNode = "SHA-256";
            }
            case 1 -> { // crypto.createHash('sha512').update(..).digest('hex')
                expectedAlgorithm = "sha512";
                expectedNode = "SHA-512";
            }
            case 2 -> { // an unrelated logger.update(..) next to a md5 hash must not attach to it
                expectedAlgorithm = "md5";
                expectedNode = "MD5";
            }
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }

        // 1. the algorithm is resolved by the shared engine
        assertThat(detectionStore.getDetectionValues())
                .extracting(IValue::asString)
                .contains(expectedAlgorithm);

        // 2. the dependent rules were followed: both update and digest were found afterwards
        List<String> actions =
                detectionStore.getChildren().stream()
                        .flatMap(child -> child.getDetectionValues().stream())
                        .filter(value -> value instanceof ValueAction<?>)
                        .map(IValue::asString)
                        .toList();
        assertThat(actions).containsExactlyInAnyOrder("update", "digest");

        // 3. the finding reaches the CBOM pipeline as a digest node
        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).asString()).isEqualTo(expectedNode);
    }
}
