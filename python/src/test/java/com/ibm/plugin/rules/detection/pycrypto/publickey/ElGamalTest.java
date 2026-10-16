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
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyLength;
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

public class ElGamalTest extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/pycrypto/publickey/ElGamalTestFile.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        switch (findingId) {
            case 0 -> {
                // ElGamal.generate(2048, None)
                assertThat(detectionStore.getDetectionValues()).hasSize(1);
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(PrivateKeyContext.class);
                IValue<Tree> v = detectionStore.getDetectionValues().get(0);
                assertThat(v).isInstanceOf(KeySize.class);
                assertThat(detectionStore.getChildren()).isEmpty();

                INode root = nodes.get(0);
                assertThat(root.getKind()).isEqualTo(PrivateKey.class);
                assertThat(root.getChildren()).hasSize(3);
                assertThat(root.asString()).isEqualTo("ElGamal");
                assertThat(root.getChildren().get(KeyGeneration.class)).isNotNull();
                assertThat(root.getChildren().get(PublicKeyEncryption.class)).isNotNull();
                assertThat(root.getChildren().get(KeyLength.class)).isNotNull();
            }
            case 1 -> {
                // ElGamal.construct((2,3,4))
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
                assertThat(root.asString()).isEqualTo("ElGamal");
                assertThat(root.getChildren().get(KeyGeneration.class)).isNotNull();
                assertThat(root.getChildren().get(PublicKeyEncryption.class)).isNotNull();
                assertThat(root.getChildren().get(PublicKeyEncryption.class).getChildren())
                        .isEmpty();
            }
            default -> throw new AssertionError("Unexpected findingId: " + findingId);
        }
    }
}
