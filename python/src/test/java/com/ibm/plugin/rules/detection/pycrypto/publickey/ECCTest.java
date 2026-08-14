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
package com.ibm.plugin.rules.detection.pycrypto.publickey;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Curve;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKeyEncryption;
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

public class ECCTest extends TestBase {

    public ECCTest() {
        super(PythonCryptoPublicKey.ECCRules());
    }

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/pycrypto/publickey/ECCTestFile.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        switch (findingId) {
            case 0 -> {
                // ECC.generate(curve="Ed25519")
                assertThat(detectionStore.getDetectionValues()).hasSize(1);
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(PrivateKeyContext.class);
                IValue<Tree> v = detectionStore.getDetectionValues().get(0);
                assertThat(v).isInstanceOf(Curve.class);
                assertThat(v.asString()).isEqualTo("Ed25519");
                assertThat(detectionStore.getChildren()).isEmpty();

                INode root = nodes.get(0);
                assertThat(root.getKind()).isEqualTo(PrivateKey.class);
                assertThat(root.getChildren()).hasSize(2);
                assertThat(root.asString()).isEqualTo("EC-Edwards25519");
                assertThat(root.getChildren().get(KeyGeneration.class)).isNotNull();

                INode pke = root.getChildren().get(PublicKeyEncryption.class);
                assertThat(pke).isNotNull();
                assertThat(pke.getChildren()).hasSize(2);
                assertThat(pke.asString()).isEqualTo("EC-Edwards25519");
                assertThat(pke.getChildren().get(EllipticCurve.class).asString())
                        .isEqualTo("Edwards25519");
                assertThat(pke.getChildren().get(Oid.class).asString())
                        .isEqualTo("1.2.840.10045.2.1");
            }
            case 1 -> {
                // ECC.construct(curve="Curve448", seed=b"A" * 56)
                assertThat(detectionStore.getDetectionValues()).hasSize(1);
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(KeyContext.class);
                IValue<Tree> v = detectionStore.getDetectionValues().get(0);
                assertThat(v).isInstanceOf(Curve.class);
                assertThat(v.asString()).isEqualTo("Curve448");
                assertThat(detectionStore.getChildren()).isEmpty();

                INode root = nodes.get(0);
                assertThat(root.getKind()).isEqualTo(Key.class);
                assertThat(root.getChildren()).hasSize(2);
                assertThat(root.asString()).isEqualTo("EC-Curve448");
                assertThat(root.getChildren().get(KeyGeneration.class)).isNotNull();

                INode pke = root.getChildren().get(PublicKeyEncryption.class);
                assertThat(pke).isNotNull();
                assertThat(pke.getChildren()).hasSize(2);
                assertThat(pke.asString()).isEqualTo("EC-Curve448");
                assertThat(pke.getChildren().get(EllipticCurve.class).asString())
                        .isEqualTo("Curve448");
                assertThat(pke.getChildren().get(Oid.class).asString())
                        .isEqualTo("1.2.840.10045.2.1");
            }
            case 2 -> {
                // ECC.import_key(...)
                assertThat(detectionStore.getDetectionValues()).hasSize(1);
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(KeyContext.class);
                assertThat(
                                ((KeyAction<Tree>) detectionStore.getDetectionValues().get(0))
                                        .getAction())
                        .isEqualTo(KeyAction.Action.GENERATION);
                assertThat(detectionStore.getChildren()).isEmpty();

                INode root = nodes.get(0);
                assertThat(root.getKind()).isEqualTo(Key.class);
                assertThat(root.getChildren()).hasSize(2);
                assertThat(root.asString()).isEqualTo("EC");
                assertThat(root.getChildren().get(KeyGeneration.class)).isNotNull();
                assertThat(
                                root.getChildren()
                                        .get(PublicKeyEncryption.class)
                                        .getChildren()
                                        .get(Oid.class)
                                        .asString())
                        .isEqualTo("1.2.840.10045.2.1");
            }
            default -> throw new AssertionError("Unexpected findingId: " + findingId);
        }
    }
}
