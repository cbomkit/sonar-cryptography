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
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.go.symbols.Symbol;
import org.sonar.go.testing.GoVerifier;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

class GoCryptoECDHTest extends TestBase {

    public GoCryptoECDHTest() {
        super(GoCryptoECDH.rules());
    }

    @Test
    void test() {
        GoVerifier.verify("rules/detection/gocrypto/GoCryptoECDHTestFile.go", this);
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
        assertThat(value0.asString()).isEqualTo("P256");

        DetectionStore<GoCheck, Tree, Symbol, GoScanContext> store1 =
                getStoreOfValueType(KeyAction.class, detectionStore.getChildren());
        assertThat(store1).isNotNull();
        assertThat(store1.getDetectionValues()).hasSize(1);
        assertThat(store1.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        IValue<Tree> value01 = store1.getDetectionValues().get(0);
        assertThat(value01).isInstanceOf(KeyAction.class);
        assertThat(value01.asString()).isEqualTo("PRIVATE_KEY_GENERATION");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // KeyAgreement
        INode keyAgreementNode = nodes.get(0);
        assertThat(keyAgreementNode.getKind()).isEqualTo(KeyAgreement.class);
        assertThat(keyAgreementNode.getChildren()).hasSize(3);
        assertThat(keyAgreementNode.asString()).isEqualTo("ECDH");

        // Oid under KeyAgreement
        INode oidNode = keyAgreementNode.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.getChildren()).isEmpty();
        assertThat(oidNode.asString()).isEqualTo("1.3.132.1.12");

        // EllipticCurve under KeyAgreement
        INode ellipticCurveNode = keyAgreementNode.getChildren().get(EllipticCurve.class);
        assertThat(ellipticCurveNode).isNotNull();
        assertThat(ellipticCurveNode.getChildren()).isEmpty();
        assertThat(ellipticCurveNode.asString()).isEqualTo("secp256r1");

        // Generate under KeyAgreement
        INode generateNode = keyAgreementNode.getChildren().get(Generate.class);
        assertThat(generateNode).isNotNull();
        assertThat(generateNode.getChildren()).isEmpty();
        assertThat(generateNode.asString()).isEqualTo("GENERATE");
    }
}
