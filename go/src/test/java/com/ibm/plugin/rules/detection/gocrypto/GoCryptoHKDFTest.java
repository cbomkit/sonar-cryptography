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
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.SaltSize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.plugin.TestBase;
import org.junit.jupiter.api.Test;
import org.sonar.go.symbols.Symbol;
import org.sonar.go.testing.GoVerifier;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

import javax.annotation.Nonnull;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class GoCryptoHKDFTest extends TestBase {

    public GoCryptoHKDFTest() {
        super(GoCryptoHKDF.rules());
    }

    @Test
    void test() {
        GoVerifier.verify("rules/detection/gocrypto/GoCryptoHKDFTestFile.go", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<GoCheck, Tree, Symbol, GoScanContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */
        assertThat(detectionStore).isNotNull();
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("HKDF");

        DetectionStore<GoCheck, Tree, Symbol, GoScanContext> store1 = getStoreOfValueType(KeySize.class, detectionStore.getChildren());
        assertThat(store1).isNotNull();
        assertThat(store1.getDetectionValues()).hasSize(1);
        assertThat(store1.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        IValue<Tree> value01 = store1.getDetectionValues().get(0);
        assertThat(value01).isInstanceOf(KeySize.class);
        assertThat(value01.asString()).isEqualTo("64");

        DetectionStore<GoCheck, Tree, Symbol, GoScanContext> store2 = getStoreOfValueType(SaltSize.class, detectionStore.getChildren());
        assertThat(store2).isNotNull();
        assertThat(store2.getDetectionValues()).hasSize(1);
        assertThat(store2.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        IValue<Tree> value02 = store2.getDetectionValues().get(0);
        assertThat(value02).isInstanceOf(SaltSize.class);
        assertThat(value02.asString()).isEqualTo("48");

        DetectionStore<GoCheck, Tree, Symbol, GoScanContext> store3 = getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
        assertThat(store3).isNotNull();
        assertThat(store3.getDetectionValues()).hasSize(1);
        assertThat(store3.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        IValue<Tree> value03 = store3.getDetectionValues().get(0);
        assertThat(value03).isInstanceOf(ValueAction.class);
        assertThat(value03.asString()).isEqualTo("SHA256");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // KeyDerivationFunction
        INode keyDerivationFunctionNode = nodes.get(0);
        assertThat(keyDerivationFunctionNode.getKind()).isEqualTo(KeyDerivationFunction.class);
        assertThat(keyDerivationFunctionNode.getChildren()).hasSize(3);
        assertThat(keyDerivationFunctionNode.asString()).isEqualTo("HKDF-SHA256");

        // SaltLength under KeyDerivationFunction
        INode saltLengthNode = keyDerivationFunctionNode.getChildren().get(SaltLength.class);
        assertThat(saltLengthNode).isNotNull();
        assertThat(saltLengthNode.getChildren()).isEmpty();
        assertThat(saltLengthNode.asString()).isEqualTo("48");

        // KeyLength under KeyDerivationFunction
        INode keyLengthNode = keyDerivationFunctionNode.getChildren().get(KeyLength.class);
        assertThat(keyLengthNode).isNotNull();
        assertThat(keyLengthNode.getChildren()).isEmpty();
        assertThat(keyLengthNode.asString()).isEqualTo("64");

        // MessageDigest under KeyDerivationFunction
        INode messageDigestNode = keyDerivationFunctionNode.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode).isNotNull();
        assertThat(messageDigestNode.getChildren()).hasSize(4);
        assertThat(messageDigestNode.asString()).isEqualTo("SHA256");

        // DigestSize under MessageDigest under KeyDerivationFunction
        INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
        assertThat(digestSizeNode).isNotNull();
        assertThat(digestSizeNode.getChildren()).isEmpty();
        assertThat(digestSizeNode.asString()).isEqualTo("256");

        // Oid under MessageDigest under KeyDerivationFunction
        INode oidNode = messageDigestNode.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.getChildren()).isEmpty();
        assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");

        // BlockSize under MessageDigest under KeyDerivationFunction
        INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
        assertThat(blockSizeNode).isNotNull();
        assertThat(blockSizeNode.getChildren()).isEmpty();
        assertThat(blockSizeNode.asString()).isEqualTo("512");

        // Digest under MessageDigest under KeyDerivationFunction
        INode digestNode = messageDigestNode.getChildren().get(Digest.class);
        assertThat(digestNode).isNotNull();
        assertThat(digestNode.getChildren()).isEmpty();
        assertThat(digestNode.asString()).isEqualTo("DIGEST");
    }
}
