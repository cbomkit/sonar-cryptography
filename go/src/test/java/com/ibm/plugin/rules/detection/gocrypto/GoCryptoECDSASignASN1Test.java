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
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.go.symbols.Symbol;
import org.sonar.go.testing.GoVerifier;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

class GoCryptoECDSASignASN1Test extends TestBase {

    public GoCryptoECDSASignASN1Test() {
        super(GoCryptoECDSA.rules());
    }

    @Test
    void test() {
        GoVerifier.verify("rules/detection/gocrypto/GoCryptoECDSASignASN1TestFile.go", this);
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
            assertThat(value0.asString()).isEqualTo("ECDSA");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // Signature
            INode signatureNode = nodes.get(0);
            assertThat(signatureNode.getKind()).isEqualTo(Signature.class);
            assertThat(signatureNode.getChildren()).hasSize(2);
            assertThat(signatureNode.asString()).isEqualTo("ECDSA");

            // PseudorandomNumberGenerator under Signature
            INode pseudorandomNumberGeneratorNode =
                    signatureNode.getChildren().get(PseudorandomNumberGenerator.class);
            assertThat(pseudorandomNumberGeneratorNode).isNotNull();
            assertThat(pseudorandomNumberGeneratorNode.getChildren()).isEmpty();
            assertThat(pseudorandomNumberGeneratorNode.asString()).isEqualTo("NATIVEPRNG");

            // EllipticCurve under Signature
            INode ellipticCurveNode = signatureNode.getChildren().get(EllipticCurve.class);
            assertThat(ellipticCurveNode).isNotNull();
            assertThat(ellipticCurveNode.getChildren()).isEmpty();
            assertThat(ellipticCurveNode.asString()).isEqualTo("secp256r1");
        } else if (findingId == 1) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SignatureContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(SignatureAction.class);
            assertThat(value0.asString()).isEqualTo("SIGN");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // Signature
            INode signatureNode1 = nodes.get(0);
            assertThat(signatureNode1.getKind()).isEqualTo(Signature.class);
            assertThat(signatureNode1.getChildren()).hasSize(3);
            assertThat(signatureNode1.asString()).isEqualTo("ECDSA");

            // Sign under Signature
            INode signNode = signatureNode1.getChildren().get(Sign.class);
            assertThat(signNode).isNotNull();
            assertThat(signNode.getChildren()).hasSize(1);
            assertThat(signNode.asString()).isEqualTo("SIGN");

            // PseudorandomNumberGenerator under Sign under Signature
            INode pseudorandomNumberGeneratorNode1 =
                    signNode.getChildren().get(PseudorandomNumberGenerator.class);
            assertThat(pseudorandomNumberGeneratorNode1).isNotNull();
            assertThat(pseudorandomNumberGeneratorNode1.getChildren()).isEmpty();
            assertThat(pseudorandomNumberGeneratorNode1.asString()).isEqualTo("NATIVEPRNG");

            // PseudorandomNumberGenerator under Signature
            INode pseudorandomNumberGeneratorNode2 =
                    signatureNode1.getChildren().get(PseudorandomNumberGenerator.class);
            assertThat(pseudorandomNumberGeneratorNode2).isNotNull();
            assertThat(pseudorandomNumberGeneratorNode2.getChildren()).isEmpty();
            assertThat(pseudorandomNumberGeneratorNode2.asString()).isEqualTo("NATIVEPRNG");

            // EllipticCurve under Signature
            INode ellipticCurveNode1 = signatureNode1.getChildren().get(EllipticCurve.class);
            assertThat(ellipticCurveNode1).isNotNull();
            assertThat(ellipticCurveNode1.getChildren()).isEmpty();
            assertThat(ellipticCurveNode1.asString()).isEqualTo("secp256r1");
        }
    }
}
