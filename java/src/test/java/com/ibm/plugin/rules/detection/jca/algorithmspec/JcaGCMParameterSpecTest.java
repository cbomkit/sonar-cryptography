/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2025 PQCA
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
package com.ibm.plugin.rules.detection.jca.algorithmspec;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.PasswordSize;
import com.ibm.engine.model.SaltSize;
import com.ibm.engine.model.TagSize;
import com.ibm.engine.model.context.AlgorithmParameterContext;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.PasswordLength;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.functionality.Tag;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class JcaGCMParameterSpecTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/jca/algorithmspec/JcaGCMParameterSpecTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        if (findingId == 0) {
            /*
             * Detection Store
             */

            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("PBKDF2WithHmacSHA256");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                    getStoreOfValueType(KeyAction.class, detectionStore.getChildren());
            assertThat(store_1.getDetectionValues()).hasSize(1);
            assertThat(store_1.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(KeyAction.class);
            assertThat(value0_1.asString()).isEqualTo("SECRET_KEY_GENERATION");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1_1 =
                    getStoreOfValueType(PasswordSize.class, store_1.getChildren());
            assertThat(store_1_1.getDetectionValues()).hasSize(3);
            assertThat(store_1_1.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value0_1_1 = store_1_1.getDetectionValues().get(0);
            assertThat(value0_1_1).isInstanceOf(PasswordSize.class);
            assertThat(value0_1_1.asString()).isEqualTo("64");

            IValue<Tree> value1_1_1 = store_1_1.getDetectionValues().get(1);
            assertThat(value1_1_1).isInstanceOf(SaltSize.class);
            assertThat(value1_1_1.asString()).isEqualTo("32");

            IValue<Tree> value2_1_1 = store_1_1.getDetectionValues().get(2);
            assertThat(value2_1_1).isInstanceOf(KeySize.class);
            assertThat(value2_1_1.asString()).isEqualTo("256");

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // SecretKey
            INode secretKeyNode = nodes.get(0);
            assertThat(secretKeyNode.getKind()).isEqualTo(SecretKey.class);
            assertThat(secretKeyNode.getChildren()).hasSize(4);
            assertThat(secretKeyNode.asString()).isEqualTo("PBKDF2");

            // KeyLength under SecretKey
            INode keyLengthNode = secretKeyNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("256");

            // SaltLength under SecretKey
            INode saltLengthNode = secretKeyNode.getChildren().get(SaltLength.class);
            assertThat(saltLengthNode).isNotNull();
            assertThat(saltLengthNode.getChildren()).isEmpty();
            assertThat(saltLengthNode.asString()).isEqualTo("32");

            // PasswordBasedKeyDerivationFunction under SecretKey
            INode passwordBasedKeyDerivationFunctionNode =
                    secretKeyNode.getChildren().get(PasswordBasedKeyDerivationFunction.class);
            assertThat(passwordBasedKeyDerivationFunctionNode).isNotNull();
            assertThat(passwordBasedKeyDerivationFunctionNode.getChildren()).hasSize(2);
            assertThat(passwordBasedKeyDerivationFunctionNode.asString())
                    .isEqualTo("PBKDF2-HMAC-SHA-256");

            // Mac under PasswordBasedKeyDerivationFunction under SecretKey
            INode macNode = passwordBasedKeyDerivationFunctionNode.getChildren().get(Mac.class);
            assertThat(macNode).isNotNull();
            assertThat(macNode.getChildren()).hasSize(3);
            assertThat(macNode.asString()).isEqualTo("HMAC-SHA-256");

            // Oid under Mac under PasswordBasedKeyDerivationFunction under SecretKey
            INode oidNode = macNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.2.840.113549.2.9");

            // MessageDigest under Mac under PasswordBasedKeyDerivationFunction under SecretKey
            INode messageDigestNode = macNode.getChildren().get(MessageDigest.class);
            assertThat(messageDigestNode).isNotNull();
            assertThat(messageDigestNode.getChildren()).hasSize(4);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA-256");

            // Oid under MessageDigest under Mac under PasswordBasedKeyDerivationFunction under
            // SecretKey
            INode oidNode1 = messageDigestNode.getChildren().get(Oid.class);
            assertThat(oidNode1).isNotNull();
            assertThat(oidNode1.getChildren()).isEmpty();
            assertThat(oidNode1.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");

            // BlockSize under MessageDigest under Mac under PasswordBasedKeyDerivationFunction
            // under SecretKey
            INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("512");

            // DigestSize under MessageDigest under Mac under PasswordBasedKeyDerivationFunction
            // under SecretKey
            INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode).isNotNull();
            assertThat(digestSizeNode.getChildren()).isEmpty();
            assertThat(digestSizeNode.asString()).isEqualTo("256");

            // Digest under MessageDigest under Mac under PasswordBasedKeyDerivationFunction under
            // SecretKey
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // Tag under Mac under PasswordBasedKeyDerivationFunction under SecretKey
            INode tagNode = macNode.getChildren().get(Tag.class);
            assertThat(tagNode).isNotNull();
            assertThat(tagNode.getChildren()).isEmpty();
            assertThat(tagNode.asString()).isEqualTo("TAG");

            // KeyDerivation under PasswordBasedKeyDerivationFunction under SecretKey
            INode keyDerivationNode =
                    passwordBasedKeyDerivationFunctionNode.getChildren().get(KeyDerivation.class);
            assertThat(keyDerivationNode).isNotNull();
            assertThat(keyDerivationNode.getChildren()).isEmpty();
            assertThat(keyDerivationNode.asString()).isEqualTo("KEYDERIVATION");

            // PasswordLength under SecretKey
            INode passwordLengthNode = secretKeyNode.getChildren().get(PasswordLength.class);
            assertThat(passwordLengthNode).isNotNull();
            assertThat(passwordLengthNode.getChildren()).isEmpty();
            assertThat(passwordLengthNode.asString()).isEqualTo("64");

        } else if (findingId == 1) {
            /*
             * Detection Store
             */

            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("AES");

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // SecretKey
            INode secretKeyNode = nodes.get(0);
            assertThat(secretKeyNode.getKind()).isEqualTo(SecretKey.class);
            assertThat(secretKeyNode.getChildren()).hasSize(1);
            assertThat(secretKeyNode.asString()).isEqualTo("AES");

            // BlockCipher under SecretKey
            INode blockCipherNode = secretKeyNode.getChildren().get(BlockCipher.class);
            assertThat(blockCipherNode).isNotNull();
            assertThat(blockCipherNode.getChildren()).hasSize(4);
            assertThat(blockCipherNode.asString()).isEqualTo("AES128");

            // BlockSize under BlockCipher under SecretKey
            INode blockSizeNode = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("128");

            // KeyLength under BlockCipher under SecretKey
            INode keyLengthNode = blockCipherNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("128");

            // Oid under BlockCipher under SecretKey
            INode oidNode = blockCipherNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.1");

            // KeyGeneration under BlockCipher under SecretKey
            INode keyGenerationNode = blockCipherNode.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode).isNotNull();
            assertThat(keyGenerationNode.getChildren()).isEmpty();
            assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");
        } else if (findingId == 2) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("AES");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store1 =
                    getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
            assertThat(store1).isNotNull();
            assertThat(store1.getDetectionValues()).hasSize(1);
            assertThat(store1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value01 = store1.getDetectionValues().get(0);
            assertThat(value01).isInstanceOf(OperationMode.class);
            assertThat(value01.asString()).isEqualTo("2");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store11 =
                    getStoreOfValueType(Algorithm.class, store1.getChildren());
            assertThat(store11).isNotNull();
            assertThat(store11.getDetectionValues()).hasSize(1);
            assertThat(store11.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value011 = store11.getDetectionValues().get(0);
            assertThat(value011).isInstanceOf(Algorithm.class);
            assertThat(value011.asString()).isEqualTo("AES");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store12 =
                    getStoreOfValueType(com.ibm.engine.model.Mode.class, store1.getChildren());
            assertThat(store12).isNotNull();
            assertThat(store12.getDetectionValues()).hasSize(2);
            assertThat(store12.getDetectionValueContext())
                    .isInstanceOf(AlgorithmParameterContext.class);
            IValue<Tree> value012 = store12.getDetectionValues().get(0);
            assertThat(value012).isInstanceOf(com.ibm.engine.model.Mode.class);
            assertThat(value012.asString()).isEqualTo("GCM");

            IValue<Tree> value112 = store12.getDetectionValues().get(1);
            assertThat(value112).isInstanceOf(TagSize.class);
            assertThat(value112.asString()).isEqualTo("128");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // SecretKey
            INode secretKeyNode = nodes.get(0);
            assertThat(secretKeyNode.getKind()).isEqualTo(SecretKey.class);
            assertThat(secretKeyNode.getChildren()).hasSize(1);
            assertThat(secretKeyNode.asString()).isEqualTo("AES");

            // AuthenticatedEncryption under SecretKey
            INode authenticatedEncryptionNode =
                    secretKeyNode.getChildren().get(AuthenticatedEncryption.class);
            assertThat(authenticatedEncryptionNode).isNotNull();
            assertThat(authenticatedEncryptionNode.getChildren()).hasSize(6);
            assertThat(authenticatedEncryptionNode.asString()).isEqualTo("AES128-GCM");

            // TagLength under AuthenticatedEncryption under SecretKey
            INode tagLengthNode = authenticatedEncryptionNode.getChildren().get(TagLength.class);
            assertThat(tagLengthNode).isNotNull();
            assertThat(tagLengthNode.getChildren()).isEmpty();
            assertThat(tagLengthNode.asString()).isEqualTo("128");

            // Mode under AuthenticatedEncryption under SecretKey
            INode modeNode = authenticatedEncryptionNode.getChildren().get(Mode.class);
            assertThat(modeNode).isNotNull();
            assertThat(modeNode.getChildren()).isEmpty();
            assertThat(modeNode.asString()).isEqualTo("GCM");

            // BlockSize under AuthenticatedEncryption under SecretKey
            INode blockSizeNode = authenticatedEncryptionNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("128");

            // Decrypt under AuthenticatedEncryption under SecretKey
            INode decryptNode = authenticatedEncryptionNode.getChildren().get(Decrypt.class);
            assertThat(decryptNode).isNotNull();
            assertThat(decryptNode.getChildren()).isEmpty();
            assertThat(decryptNode.asString()).isEqualTo("DECRYPT");

            // KeyLength under AuthenticatedEncryption under SecretKey
            INode keyLengthNode = authenticatedEncryptionNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("128");

            // Oid under AuthenticatedEncryption under SecretKey
            INode oidNode = authenticatedEncryptionNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.1");
        }
    }
}
