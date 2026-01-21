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
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Signature;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.sonar.go.symbols.Symbol;
import org.sonar.go.testing.GoVerifier;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

class GoCryptoECDSATest extends TestBase {

    public GoCryptoECDSATest() {
        super(GoCryptoECDSA.rules());
    }

    /**
     * Test ECDSA detection.
     *
     * <p>Note: This test is disabled because the sonar-go-to-slang binary does not include gc
     * export data for crypto/ecdsa. The binary has embedded support for: crypto/aes, cipher, des,
     * dsa, md5, rand, rc4, rsa, sha1, sha256, sha512, tls, x509. Packages crypto/hmac, elliptic,
     * and ecdsa are NOT included. The detection rule code is correct.
     */
    @Test
    @Disabled("sonar-go-to-slang binary lacks embedded gc export data for crypto/ecdsa")
    void test() {
        GoVerifier.verify("rules/detection/gocrypto/GoCryptoECDSATestFile.go", this);
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
        assertThat(value0.asString()).isEqualTo("ECDSA");

        // Check for child store with elliptic curve
        DetectionStore<GoCheck, Tree, Symbol, GoScanContext> curveStore =
                getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
        assertThat(curveStore).isNotNull();
        assertThat(curveStore.getDetectionValues()).hasSize(1);
        assertThat(curveStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        IValue<Tree> curveValue = curveStore.getDetectionValues().get(0);
        assertThat(curveValue).isInstanceOf(ValueAction.class);
        assertThat(curveValue.asString()).isEqualTo("P-256");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // ECDSA (Signature)
        INode ecdsaNode = nodes.get(0);
        assertThat(ecdsaNode.getKind()).isEqualTo(Signature.class);
        assertThat(ecdsaNode.getChildren()).hasSize(1);
        assertThat(ecdsaNode.asString()).isEqualTo("ECDSA");

        // EllipticCurve under ECDSA
        INode ellipticCurveNode = ecdsaNode.getChildren().get(EllipticCurve.class);
        assertThat(ellipticCurveNode).isNotNull();
        assertThat(ellipticCurveNode.getChildren()).isEmpty();
        assertThat(ellipticCurveNode.asString()).isEqualTo("P-256");
    }
}
