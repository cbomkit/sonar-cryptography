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
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.mapper.model.INode;
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

public final class PycaDiffieHellmanGenerateTest extends TestBase {

    // The key size does not yet appear because
    // of the TraceSymbol problem documented on the Github issue
    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/asymmetric/DiffieHellman/PycaDiffieHellmanGenerateTestFile.py",
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
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(PrivateKeyContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(KeyAction.class);
        assertThat(value0.asString()).isEqualTo("GENERATION");

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // PrivateKey
        INode privateKeyNode = nodes.get(0);
        assertThat(privateKeyNode.getKind()).isEqualTo(PrivateKey.class);
        assertThat(privateKeyNode.getChildren()).hasSize(2);
        assertThat(privateKeyNode.asString()).isEqualTo("FFDH");

        // KeyGeneration under PrivateKey
        INode keyGenerationNode = privateKeyNode.getChildren().get(KeyGeneration.class);
        assertThat(keyGenerationNode).isNotNull();
        assertThat(keyGenerationNode.getChildren()).isEmpty();
        assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

        // PublicKeyEncryption under PrivateKey
        INode publicKeyEncryptionNode = privateKeyNode.getChildren().get(PublicKeyEncryption.class);
        assertThat(publicKeyEncryptionNode).isNotNull();
        assertThat(publicKeyEncryptionNode.getChildren()).hasSize(1);
        assertThat(publicKeyEncryptionNode.asString()).isEqualTo("FFDH");

        // Oid under PublicKeyEncryption under PrivateKey
        INode oidNode = publicKeyEncryptionNode.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.getChildren()).isEmpty();
        assertThat(oidNode.asString()).isEqualTo("1.2.840.113549.1.3.1");
    }
}
