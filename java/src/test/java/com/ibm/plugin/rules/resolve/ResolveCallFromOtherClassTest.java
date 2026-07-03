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
package com.ibm.plugin.rules.resolve;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class ResolveCallFromOtherClassTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/resolve/ResolveCallFromOtherClassTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    @SuppressWarnings("all")
    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(value).isInstanceOf(Algorithm.class);

        if (value.asString().equals("RSA")) {
            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);
            INode node = nodes.get(0);
            assertThat(node).isInstanceOf(Key.class);
            assertThat(node.asString()).isEqualTo("RSA");

            INode blockCipher = node.getChildren().get(PublicKeyEncryption.class);
            assertThat(blockCipher).isNotNull();
            assertThat(blockCipher.asString()).isEqualTo("RSA-2048");

            INode defaultKeyLength = blockCipher.getChildren().get(KeyLength.class);
            assertThat(defaultKeyLength).isNotNull();
            assertThat(defaultKeyLength.asString()).isEqualTo("2048");
        } else if (value.asString().equals("AES")) {
            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);
            INode node = nodes.get(0);
            assertThat(node).isInstanceOf(Key.class);
            assertThat(node.asString()).isEqualTo("AES");

            INode blockCipher = node.getChildren().get(BlockCipher.class);
            assertThat(blockCipher).isNotNull();
            assertThat(blockCipher.asString()).isEqualTo("AES-128");

            INode defaultKeyLength = blockCipher.getChildren().get(KeyLength.class);
            assertThat(defaultKeyLength).isNotNull();
            assertThat(defaultKeyLength.asString()).isEqualTo("128");
        } else {
            // test fails
            assertThat(true).isFalse();
        }
    }
}
