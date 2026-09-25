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
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.DSA;
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
 * Covers all 12 rule entries in {@link OpenSSLLegacyDsa}.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 */
class OpenSSLLegacyDsaTest extends TestBase {

    private static final String DSA_OID = "1.2.840.10040.4.1";

    private int findingCount = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/legacy/OpenSSLLegacyDsaTestFile.cc", this);
        assertThat(findingCount).isEqualTo(4);
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
        assertThat(value).isInstanceOf(ValueAction.class);
        findingCount++;

        String v = value.asString();
        if (v.equals("DSA")) {
            // DSA_generate_key / DSA_generate_parameters_ex: real algorithm name resolved via
            // CxxKeyContextTranslator's DSA branch.
            assertThat(nodes).hasSize(1);
            INode n = nodes.get(0);
            assertThat(n).isInstanceOf(DSA.class);
        } else if (v.equals("DSA-SIGN")) {
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SignatureContext.class);
            assertDsa(nodes);
        } else if (v.equals("DSA-VERIFY")) {
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SignatureContext.class);
            assertDsa(nodes);
        } else if (v.equals("DSA-DH")) {
            assertThat(nodes).isEmpty();
        } else {
            throw new AssertionError("Unexpected value: " + v);
        }
    }

    private static void assertDsa(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode n = nodes.get(0);
        assertThat(n).isInstanceOf(DSA.class);
        assertThat(n.getKind()).isEqualTo(Signature.class);
        assertThat(n.asString()).isEqualTo("DSA");
        INode oid = n.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo(DSA_OID);
    }
}
