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
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.PasswordSize;
import com.ibm.engine.model.SaltSize;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.PasswordLength;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.KeyDerivation;
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

class JcaPBEKeySpecTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/jca/keyspec/JcaPBEKeySpecTestFile.java")
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
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
        assertThat(value).isInstanceOf(Algorithm.class);
        assertThat(value.asString()).isEqualTo("PBKDF2WithHmacSHA1");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store =
                getStoreOfValueType(KeySize.class, detectionStore.getChildren());
        assertThat(store).isNotNull();
        assertThat(store.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
        SecretKeyContext secretKeyContext = (SecretKeyContext) store.getDetectionValueContext();
        assertThat(secretKeyContext.kind()).isEqualTo(KeyContext.Kind.PBE);

        assertThat(store.getDetectionValues()).hasSize(3);
        List<IValue<Tree>> values = store.getDetectionValues();
        assertThat(values)
                .anyMatch(
                        v -> {
                            if (v instanceof KeySize<Tree>) {
                                return v.asString().equals("128");
                            } else if (v instanceof SaltSize<Tree>) {
                                return v.asString().equals("192");
                            } else if (v instanceof PasswordSize<Tree>) {
                                return v.asString().equals("32");
                            }
                            return false;
                        });

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
        assertThat(keyLengthNode.asString()).isEqualTo("128");

        // PasswordBasedKeyDerivationFunction under SecretKey
        INode passwordBasedKeyDerivationFunctionNode =
                secretKeyNode.getChildren().get(PasswordBasedKeyDerivationFunction.class);
        assertThat(passwordBasedKeyDerivationFunctionNode).isNotNull();
        assertThat(passwordBasedKeyDerivationFunctionNode.getChildren()).hasSize(2);
        assertThat(passwordBasedKeyDerivationFunctionNode.asString())
                .isEqualTo("PBKDF2-HMAC-SHA-1");

        // Mac under PasswordBasedKeyDerivationFunction under SecretKey
        INode macNode = passwordBasedKeyDerivationFunctionNode.getChildren().get(Mac.class);
        assertThat(macNode).isNotNull();
        assertThat(macNode.getChildren()).hasSize(3);
        assertThat(macNode.asString()).isEqualTo("HMAC-SHA-1");

        // MessageDigest under Mac under PasswordBasedKeyDerivationFunction under SecretKey
        INode messageDigestNode = macNode.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode).isNotNull();
        assertThat(messageDigestNode.getChildren()).hasSize(4);
        assertThat(messageDigestNode.asString()).isEqualTo("SHA-1");

        // BlockSize under MessageDigest under Mac under PasswordBasedKeyDerivationFunction under
        // SecretKey
        INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
        assertThat(blockSizeNode).isNotNull();
        assertThat(blockSizeNode.getChildren()).isEmpty();
        assertThat(blockSizeNode.asString()).isEqualTo("512");

        // DigestSize under MessageDigest under Mac under PasswordBasedKeyDerivationFunction under
        // SecretKey
        INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
        assertThat(digestSizeNode).isNotNull();
        assertThat(digestSizeNode.getChildren()).isEmpty();
        assertThat(digestSizeNode.asString()).isEqualTo("160");

        // Digest under MessageDigest under Mac under PasswordBasedKeyDerivationFunction under
        // SecretKey
        INode digestNode = messageDigestNode.getChildren().get(Digest.class);
        assertThat(digestNode).isNotNull();
        assertThat(digestNode.getChildren()).isEmpty();
        assertThat(digestNode.asString()).isEqualTo("DIGEST");

        // Oid under MessageDigest under Mac under PasswordBasedKeyDerivationFunction under
        // SecretKey
        INode oidNode = messageDigestNode.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.getChildren()).isEmpty();
        assertThat(oidNode.asString()).isEqualTo("1.3.14.3.2.26");

        // Tag under Mac under PasswordBasedKeyDerivationFunction under SecretKey
        INode tagNode = macNode.getChildren().get(Tag.class);
        assertThat(tagNode).isNotNull();
        assertThat(tagNode.getChildren()).isEmpty();
        assertThat(tagNode.asString()).isEqualTo("TAG");

        // Oid under Mac under PasswordBasedKeyDerivationFunction under SecretKey
        oidNode = macNode.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.getChildren()).isEmpty();
        assertThat(oidNode.asString()).isEqualTo("1.2.840.113549.2.7");

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
        assertThat(passwordLengthNode.asString()).isEqualTo("32");

        // SaltLength under SecretKey
        INode saltLengthNode = secretKeyNode.getChildren().get(SaltLength.class);
        assertThat(saltLengthNode).isNotNull();
        assertThat(saltLengthNode.getChildren()).isEmpty();
        assertThat(saltLengthNode.asString()).isEqualTo("192");
    }
}
