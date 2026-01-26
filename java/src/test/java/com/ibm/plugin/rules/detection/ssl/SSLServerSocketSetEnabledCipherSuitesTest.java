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
package com.ibm.plugin.rules.detection.ssl;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.CipherSuite;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.collections.IdentifierCollection;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class SSLServerSocketSetEnabledCipherSuitesTest extends TestBase {

    protected SSLServerSocketSetEnabledCipherSuitesTest() {
        super(SSLDetectionRules.rules());
    }

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/ssl/SSLServerSocketSetEnabledCipherSuitesTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(ProtocolContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(CipherSuite.class);
        assertThat(value0.asString()).isEqualTo("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // TLS
        INode tLSNode = nodes.get(0);
        assertThat(tLSNode.getKind()).isEqualTo(TLS.class);
        assertThat(tLSNode.getChildren()).hasSize(1);
        assertThat(tLSNode.asString()).isEqualTo("TLS");

        // CipherSuite under TLS
        INode cipherSuiteNode = tLSNode.getChildren().get(com.ibm.mapper.model.CipherSuite.class);
        assertThat(cipherSuiteNode).isNotNull();
        assertThat(cipherSuiteNode.getChildren()).hasSize(2);
        assertThat(cipherSuiteNode.asString()).isEqualTo("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256");

        // IdentifierCollection under CipherSuite under TLS
        INode identifierCollectionNode =
                cipherSuiteNode.getChildren().get(IdentifierCollection.class);
        assertThat(identifierCollectionNode).isNotNull();
        assertThat(identifierCollectionNode.getChildren()).isEmpty();
        assertThat(identifierCollectionNode.asString()).isEqualTo("[0x00, 0x6A]");

        // AssetCollection under CipherSuite under TLS
        INode assetCollectionNode = cipherSuiteNode.getChildren().get(AssetCollection.class);
        assertThat(assetCollectionNode).isNotNull();
        assertThat(assetCollectionNode.getChildren()).isEmpty();
        assertThat(assetCollectionNode.asString()).isEqualTo("[FFDH, AES256-CBC, SHA-256withDSA]");
    }
}
