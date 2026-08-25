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
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.ECDSA;
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
 * Covers all 24 rule entries in {@link OpenSSLLegacyEc}.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 */
class OpenSSLLegacyEcTest extends TestBase {

    private int ecP256Count = 0;
    private int findingCount = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/legacy/OpenSSLLegacyEcTestFile.cc", this);
        // EC_KEY_new_by_curve_name(415), EC_KEY_new_by_curve_name_ex(NULL, NULL, 415),
        // EC_GROUP_new_by_curve_name(415), EC_GROUP_new_by_curve_name_ex(NULL, NULL, 415)
        // (all literal), EC_KEY_new_by_curve_name(p256_nid) (local variable), and
        // EC_KEY_new_by_curve_name(CurveNid::P256) (scoped-enum qualified reference) all
        // resolve to "EC-P256", each via CxxSymbolResolverVisitor.
        assertThat(ecP256Count).isEqualTo(6);
        assertThat(findingCount).isGreaterThan(ecP256Count);
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
        findingCount++;

        String v = value.asString();
        if (v.equals("EC-P256")) {
            ecP256Count++;
        }
        switch (v) {
            // EC_GROUP_new_curve_GFp/GF2m fall under this shared multi-method rule (see
            // OpenSSLLegacyEc's EC_KEY_GENERATE_KEY), producing the bare "EC" value, not a
            // distinct "EC-GFP"/"EC-GF2M" string.
            case "EC", "EC-P256" -> assertEcdsa(nodes);
            case "ECDSA-SIGN" -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(SignatureContext.class);
                assertEcdsa(nodes);
            }
            case "ECDSA-VERIFY" -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(SignatureContext.class);
                assertEcdsa(nodes);
            }
            case "ECDH" -> assertEcdh(nodes);
            default -> throw new AssertionError("Unexpected value: " + v);
        }
    }

    private static void assertEcdsa(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode n = nodes.get(0);
        assertThat(n).isInstanceOf(ECDSA.class);
        assertThat(n.getKind()).isEqualTo(Signature.class);
        assertThat(n.asString()).isEqualTo("ECDSA");
    }

    private static void assertEcdh(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode n = nodes.get(0);
        assertThat(n).isInstanceOf(ECDH.class);
        assertThat(n.getKind()).isEqualTo(KeyAgreement.class);
        assertThat(n.asString()).isEqualTo("ECDH");
        INode oid = n.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo("1.3.132.1.12");
    }
}
