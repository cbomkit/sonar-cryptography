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
package com.ibm.plugin.rules.detection.jca.keyspec;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class JcaDSAPrivateKeySpecTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/jca/keyspec/JcaDSAPrivateKeySpecTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(Algorithm.class);
        assertThat(value0.asString()).isEqualTo("DSA");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                getStoreOfValueType(KeyAction.class, detectionStore.getChildren());
        assertThat(store_1.getDetectionValues()).hasSize(1);
        assertThat(store_1.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(KeyAction.class);
        assertThat(value0_1.asString()).isEqualTo("SECRET_KEY_GENERATION");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // SecretKey
        INode secretKeyNode = nodes.get(0);
        assertThat(secretKeyNode.getKind()).isEqualTo(SecretKey.class);
        assertThat(secretKeyNode.getChildren()).hasSize(2);
        assertThat(secretKeyNode.asString()).isEqualTo("DSA");

        // KeyLength under SecretKey
        INode keyLengthNode = secretKeyNode.getChildren().get(KeyLength.class);
        assertThat(keyLengthNode).isNotNull();
        assertThat(keyLengthNode.getChildren()).isEmpty();
        assertThat(keyLengthNode.asString()).isEqualTo("112");

        // Signature under SecretKey
        INode signatureNode = secretKeyNode.getChildren().get(Signature.class);
        assertThat(signatureNode).isNotNull();
        assertThat(signatureNode.getChildren()).hasSize(3);
        assertThat(signatureNode.asString()).isEqualTo("DSA-2048");

        // KeyLength under Signature under SecretKey
        INode keyLengthNode1 = signatureNode.getChildren().get(KeyLength.class);
        assertThat(keyLengthNode1).isNotNull();
        assertThat(keyLengthNode1.getChildren()).isEmpty();
        assertThat(keyLengthNode1.asString()).isEqualTo("2048");

        // KeyGeneration under Signature under SecretKey
        INode keyGenerationNode = signatureNode.getChildren().get(KeyGeneration.class);
        assertThat(keyGenerationNode).isNotNull();
        assertThat(keyGenerationNode.getChildren()).isEmpty();
        assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

        // OID under Signature under SecretKey
        INode oid = signatureNode.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.getChildren()).isEmpty();
        assertThat(oid.asString()).isEqualTo("1.2.840.10040.4.1");
    }
}
