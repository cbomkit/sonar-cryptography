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
package com.ibm.plugin.rules.detection.asymmetric.DiffieHellman;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PublicKey;
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

class PycaDiffieHellmanNumbersTest extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/asymmetric/DiffieHellman/PycaDiffieHellmanNumbersTestFile.py",
                this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(PublicKeyContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(KeyAction.class);
        assertThat(value0.asString()).isEqualTo("GENERATION");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // PublicKey
        INode publicKeyNode1 = nodes.get(0);
        assertThat(publicKeyNode1.getKind()).isEqualTo(PublicKey.class);
        assertThat(publicKeyNode1.getChildren()).hasSize(2);
        assertThat(publicKeyNode1.asString()).isEqualTo("FFDH");

        // PublicKeyEncryption under PublicKey
        INode publicKeyEncryptionNode1 =
                publicKeyNode1.getChildren().get(PublicKeyEncryption.class);
        assertThat(publicKeyEncryptionNode1).isNotNull();
        assertThat(publicKeyEncryptionNode1.getChildren()).hasSize(1);
        assertThat(publicKeyEncryptionNode1.asString()).isEqualTo("FFDH");

        // Oid under PublicKeyEncryption under PublicKey
        INode oidNode1 = publicKeyEncryptionNode1.getChildren().get(Oid.class);
        assertThat(oidNode1).isNotNull();
        assertThat(oidNode1.getChildren()).isEmpty();
        assertThat(oidNode1.asString()).isEqualTo("1.2.840.113549.1.3.1");

        // KeyGeneration under PublicKey
        INode keyGenerationNode1 = publicKeyNode1.getChildren().get(KeyGeneration.class);
        assertThat(keyGenerationNode1).isNotNull();
        assertThat(keyGenerationNode1.getChildren()).isEmpty();
        assertThat(keyGenerationNode1.asString()).isEqualTo("KEYGENERATION");
    }
}
