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
package com.ibm.plugin.rules.issues;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.plugin.TestBase;
import com.ibm.plugin.rules.detection.bc.BouncyCastleJars;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class DuplicateDependingFindingsTest extends TestBase {

    /**
     * This test is associated to the detection rule CONSTRUCTOR_1 of `OAEPEncoding`. This
     * constructor only takes an engine (from `org.bouncycastle.crypto.AsymmetricBlockCipher`). This
     * constructor has a depending detection rule `init`, that should be triggered because it is
     * called (`oaep.init(...)`). The engine has the same depending detection rule, but it shouldn't
     * be triggered because it is not called for the engine (there is no `engine.init(...)`).
     *
     * <p>This test verifies that at the level of the detection store, the `init` depending on
     * detection rule is correctly called only for the `OAEPEncoding` (expected) and not for its
     * engine (unexpected), ensuring duplicate depending on findings are not propagated.
     */
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/issues/DuplicateDependingFindingsTestFile.java")
                .withChecks(this)
                .withClassPath(BouncyCastleJars.latestJar)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        if (findingId == 0) {
            return;
        }

        /*
         * Detection Store
         */

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("OAEPEncoding");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
        assertThat(store_1.getDetectionValues()).hasSize(1);
        assertThat(store_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(OperationMode.class);
        assertThat(value0_1.asString()).isEqualTo("1");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2 =
                getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
        assertThat(store_2.getDetectionValues()).hasSize(1);
        assertThat(store_2.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_2 = store_2.getDetectionValues().get(0);
        assertThat(value0_2).isInstanceOf(ValueAction.class);
        assertThat(value0_2.asString()).isEqualTo("RSAEngine");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2_1 =
                getStoreOfValueType(OperationMode.class, store_2.getChildren());
        /* We do not want the `init` of `OAEPEncoding` to be detected as depending detection rule of `RSAEngine` */
        assertThat(store_2_1).isNull();

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // PublicKeyEncryption
        INode publicKeyEncryptionNode = nodes.get(0);
        assertThat(publicKeyEncryptionNode.getKind()).isEqualTo(PublicKeyEncryption.class);
        assertThat(publicKeyEncryptionNode.getChildren()).hasSize(3);
        assertThat(publicKeyEncryptionNode.asString()).isEqualTo("RSA-OAEP");

        // Encrypt under PublicKeyEncryption
        INode encryptNode = publicKeyEncryptionNode.getChildren().get(Encrypt.class);
        assertThat(encryptNode).isNotNull();
        assertThat(encryptNode.getChildren()).isEmpty();
        assertThat(encryptNode.asString()).isEqualTo("ENCRYPT");

        // OptimalAsymmetricEncryptionPadding under PublicKeyEncryption
        INode optimalAsymmetricEncryptionPaddingNode =
                publicKeyEncryptionNode.getChildren().get(Padding.class);
        assertThat(optimalAsymmetricEncryptionPaddingNode).isNotNull();
        assertThat(optimalAsymmetricEncryptionPaddingNode.getChildren()).isEmpty();
        assertThat(optimalAsymmetricEncryptionPaddingNode.asString()).isEqualTo("OAEP");
    }
}
