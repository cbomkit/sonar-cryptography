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
package com.ibm.plugin.rules.detection.pycrypto.cipher;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.functionality.Digest;
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

public class PKCS1OAEPTest extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/pycrypto/cipher/PKCS1OAEPTestFile.py", this);
    }

    @Test
    void testKey() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/pycrypto/cipher/PKCS1OAEPKeyTestFile.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        // cipher = PKCS1_OAEP.new(key, SHA256)
        assertThat(findingId).isZero();

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(detectionStore.getDetectionValueContext().get("kind")).contains("pycrypto-oaep");
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(ValueAction.class);
        assertThat(value.asString()).isEqualTo("PKCS1_OAEP");

        // the fixtures never call encrypt/decrypt
        assertThat(getStoreOfValueType(CipherAction.class, detectionStore.getChildren())).isNull();

        // the key argument (RSA.import_key) and the hashAlgo argument (SHA256)
        List<DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>> algorithmStores =
                getStoresOfValueType(Algorithm.class, detectionStore.getChildren());
        assertThat(algorithmStores).hasSize(2);
        assertThat(algorithmStores)
                .allSatisfy(
                        store -> {
                            assertThat(store.getDetectionValues()).hasSize(1);
                            assertThat(store.getDetectionValues().get(0))
                                    .isInstanceOf(Algorithm.class);
                            assertThat(store.getDetectionValueContext())
                                    .isInstanceOf(CipherContext.class);
                        });
        assertThat(algorithmStores)
                .extracting(store -> store.getDetectionValues().get(0).asString())
                .containsExactlyInAnyOrder("import_key", "SHA256");

        assertThat(nodes).hasSize(1);
        INode cipher = nodes.get(0);
        assertThat(cipher.getKind()).isEqualTo(PublicKeyEncryption.class);
        assertThat(cipher.getChildren()).hasSize(4);
        assertThat(cipher.asString()).isEqualTo("RSA-OAEP");

        INode oid = cipher.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.getChildren()).isEmpty();
        assertThat(oid.asString()).isEqualTo("1.2.840.113549.1.1.7");

        INode padding = cipher.getChildren().get(Padding.class);
        assertThat(padding).isNotNull();
        assertThat(padding.getChildren()).isEmpty();
        assertThat(padding.asString()).isEqualTo("OAEP");

        INode messageDigest = cipher.getChildren().get(MessageDigest.class);
        assertThat(messageDigest).isNotNull();
        assertThat(messageDigest.getChildren()).hasSize(4);
        assertThat(messageDigest.asString()).isEqualTo("SHA-256");

        INode mdOid = messageDigest.getChildren().get(Oid.class);
        assertThat(mdOid).isNotNull();
        assertThat(mdOid.getChildren()).isEmpty();
        assertThat(mdOid.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");

        INode digest = messageDigest.getChildren().get(Digest.class);
        assertThat(digest).isNotNull();
        assertThat(digest.getChildren()).isEmpty();
        assertThat(digest.asString()).isEqualTo("DIGEST");

        INode blockSize = messageDigest.getChildren().get(BlockSize.class);
        assertThat(blockSize).isNotNull();
        assertThat(blockSize.getChildren()).isEmpty();
        assertThat(blockSize.asString()).isEqualTo("512");

        INode digestSize = messageDigest.getChildren().get(DigestSize.class);
        assertThat(digestSize).isNotNull();
        assertThat(digestSize.getChildren()).isEmpty();
        assertThat(digestSize.asString()).isEqualTo("256");

        INode key = cipher.getChildren().get(Key.class);
        assertThat(key).isNotNull();
        assertThat(key.asString()).isEqualTo("RSA");

        INode keyGen = key.getChildren().get(KeyGeneration.class);
        assertThat(keyGen).isNotNull();
        assertThat(keyGen.asString()).isEqualTo("KEYGENERATION");

        INode pke = key.getChildren().get(PublicKeyEncryption.class);
        assertThat(pke).isNotNull();
        assertThat(pke.asString()).isEqualTo("RSA");

        INode pkeOID = pke.getChildren().get(Oid.class);
        assertThat(pkeOID).isNotNull();
        assertThat(pkeOID.asString()).isEqualTo("1.2.840.113549.1.1.1");
    }
}
