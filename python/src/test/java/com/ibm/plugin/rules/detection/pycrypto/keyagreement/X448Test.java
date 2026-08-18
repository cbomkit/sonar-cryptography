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
package com.ibm.plugin.rules.detection.pycrypto.keyagreement;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.algorithms.X448;
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

public class X448Test extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/pycrypto/keyagreement/X448TestFile.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        if (findingId == 1) {
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(KeyAgreementContext.class);
            assertThat(detectionStore.getDetectionValues().get(0)).isInstanceOf(ValueAction.class);
            assertThat(detectionStore.getDetectionValues().get(0).asString()).isEqualTo("ECDH");

            assertThat(nodes).hasSize(1);
            INode root = nodes.get(0);
            assertThat(root.getKind()).isEqualTo(KeyAgreement.class);
            assertThat(root).isInstanceOf(X448.class);
            assertThat(root.asString()).isEqualTo("x448");

            assertThat(root.getChildren().get(Oid.class)).isNotNull();
            assertThat(root.getChildren().get(Oid.class).asString()).isEqualTo("1.3.101.111");
            assertThat(root.getChildren().get(EllipticCurve.class)).isNotNull();
            assertThat(root.getChildren().get(EllipticCurve.class).asString())
                    .isEqualTo("Curve448");
            assertThat(root.getChildren().get(KeyGeneration.class)).isNotNull();
            assertThat(root.getChildren().get(KeyGeneration.class).asString())
                    .isEqualTo("KEYGENERATION");
            assertThat(root.getChildren().get(PublicKey.class)).isNotNull();
            assertThat(root.getChildren().get(PublicKey.class).asString()).isEqualTo("EC-Curve448");
            assertThat(root.getChildren().get(PrivateKey.class)).isNotNull();
            assertThat(root.getChildren().get(PrivateKey.class).asString())
                    .isEqualTo("EC-Curve448");
        }
    }
}
