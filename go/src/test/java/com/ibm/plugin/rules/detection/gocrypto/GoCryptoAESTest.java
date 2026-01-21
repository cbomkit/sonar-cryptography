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
package com.ibm.plugin.rules.detection.gocrypto;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.go.GoScanContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import org.junit.jupiter.api.Test;
import org.sonar.go.symbols.Symbol;
import org.sonar.go.testing.GoVerifier;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

import javax.annotation.Nonnull;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class GoCryptoAESTest extends TestBase {

    /**
     * Tests detection of aes.NewCipher() calls from crypto/aes package.
     *
     * <p>Note: This test requires Go AST parsing support which is not yet available in the test
     * infrastructure. The GoVerifier currently only validates comment-based issue expectations but
     * cannot trigger actual detection rules without a Go parser.
     *
     * <p>Once Go parser integration is available (similar to python-checks-testkit for Python),
     * this test will verify:
     *
     * <ul>
     *   <li>Detection store contains Algorithm "AES" with CipherContext
     *   <li>Translation produces BlockCipher node with value "AES"
     * </ul>
     */
    @Test
    void test() {
        GoVerifier.verify("rules/detection/gocrypto/GoCryptoAESTestFile.go", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<GoCheck, Tree, Symbol, GoScanContext> detectionStore,
            @Nonnull List<INode> nodes) {

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node).isInstanceOf(BlockCipher.class);
        assertThat(node.asString()).isEqualTo("AES");
    }
}
