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
package com.ibm.plugin.rules.detection.aead;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

class PycaChaCha20Poly1305Test extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/aead/PycaChaCha20Poly1305TestFile.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
        assertThat(value).isInstanceOf(KeyAction.class);
        assertThat(value.asString()).isEqualTo("GENERATION");

        assertThat(detectionStore.getChildren()).hasSize(2);

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store =
                detectionStore.getChildren().get(0);
        IValue<Tree> decryptValue = store.getDetectionValues().get(0);
        assertThat(store.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(decryptValue).isInstanceOf(CipherAction.class);
        assertThat(decryptValue.asString()).isEqualTo("ENCRYPT");

        store = detectionStore.getChildren().get(1);
        IValue<Tree> encryptValue = store.getDetectionValues().get(0);
        assertThat(store.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(encryptValue).isInstanceOf(CipherAction.class);
        assertThat(encryptValue.asString()).isEqualTo("DECRYPT");

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // SecretKey
        INode secretKeyNode = nodes.get(0);
        assertThat(secretKeyNode.getKind()).isEqualTo(SecretKey.class);
        assertThat(secretKeyNode.getChildren()).hasSize(4);
        assertThat(secretKeyNode.asString()).isEqualTo("ChaCha20");

        // Encrypt under SecretKey
        INode encryptNode = secretKeyNode.getChildren().get(Encrypt.class);
        assertThat(encryptNode).isNotNull();
        assertThat(encryptNode.getChildren()).isEmpty();
        assertThat(encryptNode.asString()).isEqualTo("ENCRYPT");

        // Decrypt under SecretKey
        INode decryptNode = secretKeyNode.getChildren().get(Decrypt.class);
        assertThat(decryptNode).isNotNull();
        assertThat(decryptNode.getChildren()).isEmpty();
        assertThat(decryptNode.asString()).isEqualTo("DECRYPT");

        // KeyGeneration under SecretKey
        INode keyGenerationNode = secretKeyNode.getChildren().get(KeyGeneration.class);
        assertThat(keyGenerationNode).isNotNull();
        assertThat(keyGenerationNode.getChildren()).isEmpty();
        assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

        // AuthenticatedEncryption under SecretKey
        INode authenticatedEncryptionNode =
                secretKeyNode.getChildren().get(AuthenticatedEncryption.class);
        assertThat(authenticatedEncryptionNode).isNotNull();
        assertThat(authenticatedEncryptionNode.getChildren()).hasSize(1);
        assertThat(authenticatedEncryptionNode.asString()).isEqualTo("ChaCha20-Poly1305");

        // MessageDigest under AuthenticatedEncryption under SecretKey
        INode messageDigestNode =
                authenticatedEncryptionNode.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode).isNotNull();
        assertThat(messageDigestNode.getChildren()).hasSize(1);
        assertThat(messageDigestNode.asString()).isEqualTo("Poly1305");

        // Digest under MessageDigest under AuthenticatedEncryption under SecretKey
        INode digestNode = messageDigestNode.getChildren().get(Digest.class);
        assertThat(digestNode).isNotNull();
        assertThat(digestNode.getChildren()).isEmpty();
        assertThat(digestNode.asString()).isEqualTo("DIGEST");
    }
}
