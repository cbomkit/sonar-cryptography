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

class ProbeGoTraceTest extends TestBase {

    public ProbeGoTraceTest() {
        super(GoCryptoECDSA.rules());
    }

    @Test
    void test() {
        GoVerifier.verify("rules/detection/gocrypto/ProbeGoTraceTestFile.go", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<GoCheck, Tree, Symbol, GoScanContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore).isNotNull();
        assertThat(nodes).hasSize(1);
        INode signatureNode = nodes.get(0);
        assertThat(signatureNode.getKind()).isEqualTo(Signature.class);

        if (findingId == 0) {
            // First key finding: decoyKey GenerateKey with P-521
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            assertThat(signatureNode.asString()).isEqualTo("ECDSA-secp521r1");
        } else if (findingId == 1) {
            // Second key finding: privateKey GenerateKey with P-256
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            assertThat(signatureNode.asString()).isEqualTo("ECDSA-secp256r1");
        } else if (findingId == 2) {
            // SignASN1 signature finding
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SignatureContext.class);
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(SignatureAction.class);
            assertThat(value0.asString()).isEqualTo("SIGN");
            assertThat(signatureNode.asString()).isEqualTo("ECDSA-secp256r1");
            assertThat(signatureNode.getChildren()).hasSize(3);

            INode signNode = signatureNode.getChildren().get(Sign.class);
            assertThat(signNode).isNotNull();
            assertThat(signNode.asString()).isEqualTo("SIGN");

            INode pseudorandomNumberGeneratorNode =
                    signatureNode.getChildren().get(PseudorandomNumberGenerator.class);
            assertThat(pseudorandomNumberGeneratorNode).isNotNull();
            assertThat(pseudorandomNumberGeneratorNode.getChildren()).isEmpty();
            assertThat(pseudorandomNumberGeneratorNode.asString()).isEqualTo("NATIVEPRNG");

            INode ellipticCurveNode = signatureNode.getChildren().get(EllipticCurve.class);
            assertThat(ellipticCurveNode).isNotNull();
            assertThat(ellipticCurveNode.getChildren()).isEmpty();
            assertThat(ellipticCurveNode.asString()).isEqualTo("secp256r1");
        }
    }
}
