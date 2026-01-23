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
import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.plugin.TestBase;
import org.junit.jupiter.api.Test;
import org.sonar.go.symbols.Symbol;
import org.sonar.go.testing.GoVerifier;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

import javax.annotation.Nonnull;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class GoCryptoDSATest extends TestBase {

    public GoCryptoDSATest() {
        super(GoCryptoDSA.rules());
    }

    @Test
    void test() {
        GoVerifier.verify("rules/detection/gocrypto/GoCryptoDSATestFile.go", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<GoCheck, Tree, Symbol, GoScanContext> detectionStore,
            @Nonnull List<INode> nodes) {
        if (findingId == 0) {
            // dsa.GenerateKey - with depending GENERATE_PARAMETERS detection
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("DSA");

            // Child detection: AlgorithmParameter from GenerateParameters
            DetectionStore<GoCheck, Tree, Symbol, GoScanContext> paramStore =
                    getStoreOfValueType(AlgorithmParameter.class, detectionStore.getChildren());
            assertThat(paramStore).isNotNull();
            assertThat(paramStore.getDetectionValues()).hasSize(1);
            assertThat(paramStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            IValue<Tree> paramValue = paramStore.getDetectionValues().get(0);
            assertThat(paramValue).isInstanceOf(AlgorithmParameter.class);
            assertThat(paramValue.asString()).isEqualTo("L2048N256");

            // Translation: Signature DSA with KeyLength 2048
            assertThat(nodes).hasSize(1);
            INode signatureNode = nodes.get(0);
            assertThat(signatureNode.getKind()).isEqualTo(Signature.class);
            assertThat(signatureNode.asString()).isEqualTo("DSA");

            INode keyLengthNode = signatureNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.asString()).isEqualTo("2048");

            INode oidNode = signatureNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.asString()).isEqualTo("1.2.840.10040.4.1");
        } else if (findingId == 1) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(SignatureAction.class);
            assertThat(value0.asString()).isEqualTo("SIGN");

            DetectionStore<GoCheck, Tree, Symbol, GoScanContext> store1 = getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
            assertThat(store1).isNotNull();
            assertThat(store1.getDetectionValues()).hasSize(1);
            assertThat(store1.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            IValue<Tree> value01 = store1.getDetectionValues().get(0);
            assertThat(value01).isInstanceOf(ValueAction.class);
            assertThat(value01.asString()).isEqualTo("DSA");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // Signature
            INode signatureNode = nodes.get(0);
            assertThat(signatureNode.getKind()).isEqualTo(Signature.class);
            assertThat(signatureNode.getChildren()).hasSize(3);
            assertThat(signatureNode.asString()).isEqualTo("DSA");

            // KeyLength under Signature
            INode keyLengthNode = signatureNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("2048");

            // Sign under Signature
            INode signNode = signatureNode.getChildren().get(Sign.class);
            assertThat(signNode).isNotNull();
            assertThat(signNode.getChildren()).isEmpty();
            assertThat(signNode.asString()).isEqualTo("SIGN");

            // Oid under Signature
            INode oidNode = signatureNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.2.840.10040.4.1");
        } else if (findingId == 2) {

        }
    }
}
