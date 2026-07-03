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
package com.ibm.plugin.rules.detection.jca.digest;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class JcaMessageDigestGetInstanceMd5Test extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/jca/digest/JcaMessageDigestGetInstanceMd5TestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        assertThat(value).isInstanceOf(Algorithm.class);
        assertThat(value.asString()).isEqualTo("MD5");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node).isInstanceOf(MessageDigest.class);
        assertThat(node.getChildren()).hasSize(3);
        assertThat(node.asString()).isEqualTo("MD5");

        INode digest = node.getChildren().get(Digest.class);
        assertThat(digest).isNotNull();
        assertThat(digest.getChildren()).isEmpty();
        assertThat(digest.asString()).isEqualTo("DIGEST");

        INode digestSize = node.getChildren().get(DigestSize.class);
        assertThat(digestSize).isNotNull();
        assertThat(digestSize.getChildren()).isEmpty();
        assertThat(digestSize.asString()).isEqualTo("128");

        INode blockSize = node.getChildren().get(BlockSize.class);
        assertThat(blockSize).isNotNull();
        assertThat(blockSize.getChildren()).isEmpty();
        assertThat(blockSize.asString()).isEqualTo("512");
    }
}
