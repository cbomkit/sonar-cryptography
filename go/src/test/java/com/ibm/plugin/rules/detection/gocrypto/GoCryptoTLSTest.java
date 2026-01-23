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
import com.ibm.engine.model.Protocol;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.plugin.TestBase;
import org.junit.jupiter.api.Test;
import org.sonar.go.symbols.Symbol;
import org.sonar.go.testing.GoVerifier;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

import javax.annotation.Nonnull;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class GoCryptoTLSTest extends TestBase {

    public GoCryptoTLSTest() {
        super(GoCryptoTLS.rules());
    }

    @Test
    void test() {
        GoVerifier.verify("rules/detection/gocrypto/GoCryptoTLSTestFile.go", this);
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
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(ProtocolContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("TLS");

        DetectionStore<GoCheck, Tree, Symbol, GoScanContext> store1 = getStoreOfValueType(Protocol.class, detectionStore.getChildren());
        assertThat(store1).isNotNull();
        assertThat(store1.getDetectionValues()).hasSize(1);
        assertThat(store1.getDetectionValueContext()).isInstanceOf(ProtocolContext.class);
        IValue<Tree> value01 = store1.getDetectionValues().get(0);
        assertThat(value01).isInstanceOf(Protocol.class);
        assertThat(value01.asString()).isEqualTo("VersionTLS12");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // TLS
        INode tLSNode = nodes.get(0);
        assertThat(tLSNode.getKind()).isEqualTo(TLS.class);
        assertThat(tLSNode.getChildren()).hasSize(2);
        assertThat(tLSNode.asString()).isEqualTo("TLSv1.2");

        // CipherSuiteCollection under TLS
        INode cipherSuiteCollectionNode = tLSNode.getChildren().get(CipherSuiteCollection.class);
        assertThat(cipherSuiteCollectionNode).isNotNull();
        assertThat(cipherSuiteCollectionNode.getChildren()).isEmpty();
        assertThat(cipherSuiteCollectionNode.asString()).isEqualTo("[TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256]");

        // Version under TLS
        INode versionNode = tLSNode.getChildren().get(Version.class);
        assertThat(versionNode).isNotNull();
        assertThat(versionNode.getChildren()).isEmpty();
        assertThat(versionNode.asString()).isEqualTo("1.2");
    }
}
