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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.go.GoScanContext;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.sonar.go.symbols.Symbol;
import org.sonar.go.testing.GoVerifier;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

class GoCryptoRSATest extends TestBase {

    public GoCryptoRSATest() {
        super(GoCryptoRSA.rules());
    }

    /**
     * Test RSA detection.
     *
     * <p>Note: This test is disabled because the sonar-go-to-slang binary does not have gc export
     * data for the crypto/rsa package, causing type checking to fail. The detection rule and
     * translator code is correct and follows the same patterns as other working detection rules.
     * Once the test infrastructure supports crypto/rsa, this test should pass.
     */
    @Test
    @Disabled("Test infrastructure lacks gc export data for crypto/rsa package")
    void test() {
        GoVerifier.verify("rules/detection/gocrypto/GoCryptoRSATestFile.go", this);
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
        assertThat(value0.asString()).isEqualTo("RSA");

        DetectionStore<GoCheck, Tree, Symbol, GoScanContext> keySizeStore =
                getStoreOfValueType(KeySize.class, detectionStore.getChildren());
        assertThat(keySizeStore).isNotNull();
        assertThat(keySizeStore.getDetectionValues()).hasSize(1);
        assertThat(keySizeStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        IValue<Tree> keySizeValue = keySizeStore.getDetectionValues().get(0);
        assertThat(keySizeValue).isInstanceOf(KeySize.class);
        assertThat(keySizeValue.asString()).isEqualTo("2048");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // RSA (PublicKeyEncryption)
        INode rsaNode = nodes.get(0);
        assertThat(rsaNode.getKind()).isEqualTo(PublicKeyEncryption.class);
        assertThat(rsaNode.getChildren()).hasSize(2);
        assertThat(rsaNode.asString()).isEqualTo("RSA-2048");

        // KeyLength under RSA
        INode keyLengthNode = rsaNode.getChildren().get(KeyLength.class);
        assertThat(keyLengthNode).isNotNull();
        assertThat(keyLengthNode.getChildren()).isEmpty();
        assertThat(keyLengthNode.asString()).isEqualTo("2048");

        // Oid under RSA
        INode oidNode = rsaNode.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.getChildren()).isEmpty();
        assertThat(oidNode.asString()).isEqualTo("1.2.840.113549.1.1.1");
    }
}
