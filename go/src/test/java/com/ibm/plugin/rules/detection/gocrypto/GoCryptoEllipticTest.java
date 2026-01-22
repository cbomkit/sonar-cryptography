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
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.plugin.TestBase;
import org.junit.jupiter.api.Test;
import org.sonar.go.symbols.Symbol;
import org.sonar.go.testing.GoVerifier;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

import javax.annotation.Nonnull;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class GoCryptoEllipticTest extends TestBase {

    public GoCryptoEllipticTest() {
        super(GoCryptoElliptic.rules());
    }

    @Test
    void test() {
        GoVerifier.verify("rules/detection/gocrypto/GoCryptoEllipticTestFile.go", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<GoCheck, Tree, Symbol, GoScanContext> detectionStore,
            @Nonnull List<INode> nodes) {
        if (findingId == 0) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("P-224");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // PublicKeyEncryption
            INode publicKeyEncryptionNode = nodes.get(0);
            assertThat(publicKeyEncryptionNode.getKind()).isEqualTo(PublicKeyEncryption.class);
            assertThat(publicKeyEncryptionNode.getChildren()).hasSize(2);
            assertThat(publicKeyEncryptionNode.asString()).isEqualTo("EC-secp224r1");

            // Oid under PublicKeyEncryption
            INode oidNode = publicKeyEncryptionNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.2.840.10045.2.1");

            // EllipticCurve under PublicKeyEncryption
            INode ellipticCurveNode = publicKeyEncryptionNode.getChildren().get(EllipticCurve.class);
            assertThat(ellipticCurveNode).isNotNull();
            assertThat(ellipticCurveNode.getChildren()).isEmpty();
            assertThat(ellipticCurveNode.asString()).isEqualTo("secp224r1");
        } else if (findingId == 1) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("P-256");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // PublicKeyEncryption
            INode publicKeyEncryptionNode = nodes.get(0);
            assertThat(publicKeyEncryptionNode.getKind()).isEqualTo(PublicKeyEncryption.class);
            assertThat(publicKeyEncryptionNode.getChildren()).hasSize(2);
            assertThat(publicKeyEncryptionNode.asString()).isEqualTo("EC-secp256r1");

            // Oid under PublicKeyEncryption
            INode oidNode = publicKeyEncryptionNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.2.840.10045.2.1");

            // EllipticCurve under PublicKeyEncryption
            INode ellipticCurveNode = publicKeyEncryptionNode.getChildren().get(EllipticCurve.class);
            assertThat(ellipticCurveNode).isNotNull();
            assertThat(ellipticCurveNode.getChildren()).isEmpty();
            assertThat(ellipticCurveNode.asString()).isEqualTo("secp256r1");
        } else if (findingId == 2) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("P-384");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // PublicKeyEncryption
            INode publicKeyEncryptionNode = nodes.get(0);
            assertThat(publicKeyEncryptionNode.getKind()).isEqualTo(PublicKeyEncryption.class);
            assertThat(publicKeyEncryptionNode.getChildren()).hasSize(2);
            assertThat(publicKeyEncryptionNode.asString()).isEqualTo("EC-secp384r1");

            // Oid under PublicKeyEncryption
            INode oidNode = publicKeyEncryptionNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.2.840.10045.2.1");

            // EllipticCurve under PublicKeyEncryption
            INode ellipticCurveNode = publicKeyEncryptionNode.getChildren().get(EllipticCurve.class);
            assertThat(ellipticCurveNode).isNotNull();
            assertThat(ellipticCurveNode.getChildren()).isEmpty();
            assertThat(ellipticCurveNode.asString()).isEqualTo("secp384r1");
        } else if (findingId == 3) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("P-521");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // PublicKeyEncryption
            INode publicKeyEncryptionNode = nodes.get(0);
            assertThat(publicKeyEncryptionNode.getKind()).isEqualTo(PublicKeyEncryption.class);
            assertThat(publicKeyEncryptionNode.getChildren()).hasSize(2);
            assertThat(publicKeyEncryptionNode.asString()).isEqualTo("EC-secp521r1");

            // Oid under PublicKeyEncryption
            INode oidNode = publicKeyEncryptionNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.2.840.10045.2.1");

            // EllipticCurve under PublicKeyEncryption
            INode ellipticCurveNode = publicKeyEncryptionNode.getChildren().get(EllipticCurve.class);
            assertThat(ellipticCurveNode).isNotNull();
            assertThat(ellipticCurveNode.getChildren()).isEmpty();
            assertThat(ellipticCurveNode.asString()).isEqualTo("secp521r1");
        }
    }
}
