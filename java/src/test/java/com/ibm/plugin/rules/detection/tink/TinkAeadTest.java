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
package com.ibm.plugin.rules.detection.tink;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class TinkAeadTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/tink/TinkAeadTestFile.java")
                .withChecks(this)
                .withClassPath(
                        com.google.common.collect.ImmutableList.of(
                                new java.io.File(
                                        System.getProperty("user.home")
                                                + "/.m2/repository/com/google/crypto/tink/tink/1.21.0/tink-1.21.0.jar")))
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
        assertThat(detectionStore.getDetectionValueContext())
                .isInstanceOfAny(CipherContext.class, MacContext.class, SignatureContext.class);
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(ValueAction.class);
        assertThat(value.asString())
                .isIn(
                        "AES128_GCM",
                        "AES256_GCM",
                        "AES128_CTR_HMAC_SHA256",
                        "AES256_CTR_HMAC_SHA256",
                        "HMAC_SHA256_128BITTAG",
                        "HMAC_SHA256_256BITTAG",
                        "HMAC_SHA512_256BITTAG",
                        "HMAC_SHA512_512BITTAG",
                        "AES_CMAC",
                        "ECDSA_P256",
                        "ECDSA_P384",
                        "ECDSA_P521",
                        "ED25519",
                        "RSA_SSA_PKCS1_3072_SHA256_F4",
                        "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                        "ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256");

        // Translation only implemented for AEAD templates — Mac/Hybrid/Signature return empty nodes
        if (!nodes.isEmpty()) {
            INode node = nodes.get(0);
            assertThat(node.getKind()).isIn(AuthenticatedEncryption.class, BlockCipher.class);
            assertThat(node.asString()).isEqualTo("AES");
        }
    }
}
