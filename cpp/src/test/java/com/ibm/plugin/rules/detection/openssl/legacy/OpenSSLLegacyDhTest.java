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
package com.ibm.plugin.rules.detection.openssl.legacy;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * Covers all rule entries in {@link OpenSSLLegacyDh}.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 */
class OpenSSLLegacyDhTest extends TestBase {

    private static final String DH_OID = "1.2.840.113549.1.3.1";

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/legacy/OpenSSLLegacyDhTestFile.cc", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<AstNode> value = detectionStore.getDetectionValues().get(0);

        String v = value.asString();
        if (v.equals("DH")) {
            if (detectionStore.getDetectionValueContext() instanceof PrivateKeyContext) {
                // DH_generate_key(dh), dh holding the parameters of DH_generate_parameters_ex
                assertDhPrivateKey(nodes);
            } else if (detectionStore.getDetectionValueContext() instanceof KeyContext) {
                // DH_generate_parameters_ex(dh, 2048, ...)
                assertDhParameters(nodes);
            } else if (detectionStore.getDetectionValueContext() instanceof KeyAgreementContext) {
                assertDhKa(nodes);
            } else {
                throw new AssertionError(
                        "Unexpected context for DH: " + detectionStore.getDetectionValueContext());
            }
        } else if (v.equals("DH-1024-160")) {
            assertNamedGroup(detectionStore, value, nodes, "DH-1024-160", "FFDH-1024");
        } else if (v.equals("DH-2048-224")) {
            assertNamedGroup(detectionStore, value, nodes, "DH-2048-224", "FFDH-2048");
        } else if (v.equals("DH-2048-256")) {
            assertNamedGroup(detectionStore, value, nodes, "DH-2048-256", "FFDH-2048");
        } else {
            throw new AssertionError("Unexpected value: " + v);
        }
    }

    private static void assertDhParameters(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode n = nodes.get(0);
        assertThat(n).isInstanceOf(DH.class);
        assertThat(n.getKind()).isEqualTo(PublicKeyEncryption.class);
        assertThat(n.asString()).isEqualTo("FFDH-2048");
        INode oid = n.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo(DH_OID);
    }

    private static void assertDhPrivateKey(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0)).isInstanceOf(PrivateKey.class);
        assertDhParameters(List.of(nodes.get(0).getChildren().get(PublicKeyEncryption.class)));
    }

    private static void assertDhKa(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode n = nodes.get(0);
        assertThat(n).isInstanceOf(DH.class);
        assertThat(n.getKind()).isEqualTo(KeyAgreement.class);
        assertThat(n.asString()).isEqualTo("FFDH");
        INode oid = n.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo(DH_OID);
    }

    private static void assertNamedGroup(
            DetectionStore<
                            SquidCheck<?>,
                            AstNode,
                            Symbol,
                            SquidAstVisitorContext<? extends Grammar>>
                    detectionStore,
            IValue<AstNode> value,
            List<INode> nodes,
            String expected,
            String expectedAsset) {
        // RFC 5114 group: finite-field DH with the group's prime size
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(value.asString()).isEqualTo(expected);
        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0)).isInstanceOf(DH.class);
        assertThat(nodes.get(0).asString()).isEqualTo(expectedAsset);
    }
}
