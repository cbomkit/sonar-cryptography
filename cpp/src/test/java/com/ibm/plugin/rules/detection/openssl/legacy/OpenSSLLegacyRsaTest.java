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
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.RSA;
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
 * Covers all 31 rule entries in {@link OpenSSLLegacyRsa}.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 */
class OpenSSLLegacyRsaTest extends TestBase {

    private static final String RSA_OID = "1.2.840.113549.1.1.1";

    private int md5SignCount = 0;
    private int md5VerifyCount = 0;
    private int findingCount = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/legacy/OpenSSLLegacyRsaTestFile.cc", this);
        // RSA_sign(md5_nid, ...) / RSA_verify(md5_nid, ...): md5_nid is a plain local variable
        // (not an enum constant), resolved via CxxSymbolResolverVisitor.
        assertThat(md5SignCount).isEqualTo(1);
        assertThat(md5VerifyCount).isEqualTo(1);
        assertThat(findingCount).isEqualTo(27);
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
        switch (v) {
            case "RSA" -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(KeyContext.class);
                assertRsaPke(nodes);
            }
            case "RSA-ENCRYPT",
                    "RSA-DECRYPT",
                    "RSA-OAEP",
                    "RSA-PKCS1",
                    "RSA-X931",
                    "RSA-NO-PAD",
                    "RSA-NO-PADDING",
                    "RSA-PKCS1-TYPE2" -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(CipherContext.class);
                assertThat(nodes).isEmpty();
            }
            case "RSA-PSS" -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(SignatureContext.class);
                assertRsaSig(nodes, "RSA-PKCS1-1.5", RSA_OID);
            }
            case "RSA-SIGN-SHA256" -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(SignatureContext.class);
                assertRsaSig(nodes, "RSA-PKCS1-1.5-SHA-256", "1.2.840.113549.1.1.11");
            }
            case "RSA-VERIFY-SHA256" -> {
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(SignatureContext.class);
                assertRsaSig(nodes, "RSA-PKCS1-1.5-SHA-256", "1.2.840.113549.1.1.11");
            }
            case "RSA-SIGN-MD5" -> {
                md5SignCount++;
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(SignatureContext.class);
                // CxxSignatureContextTranslator has no MD5 branch for RSA- values, so the
                // digest is dropped: same bare RSA-PKCS1-1.5 node as the generic RSA-PSS case.
                assertRsaSig(nodes, "RSA-PKCS1-1.5", RSA_OID);
            }
            case "RSA-VERIFY-MD5" -> {
                md5VerifyCount++;
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(SignatureContext.class);
                assertRsaSig(nodes, "RSA-PKCS1-1.5", RSA_OID);
            }
            case "RSA-OAEP-MGF1" -> {
                // RSA_padding_add/check_PKCS1_OAEP_mgf1: parameters carry no algorithm name to
                // trace, so this resolves to no node.
                assertThat(detectionStore.getDetectionValueContext())
                        .isInstanceOf(CipherContext.class);
                assertThat(nodes).isEmpty();
            }
            default -> throw new AssertionError("Unexpected value: " + v);
        }
    }

    private static void assertRsaPke(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode n = nodes.get(0);
        assertThat(n).isInstanceOf(RSA.class);
        assertThat(n.getKind()).isEqualTo(PublicKeyEncryption.class);
        assertThat(n.asString()).isEqualTo("RSA");
        INode oid = n.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo(RSA_OID);
    }

    private static void assertRsaSig(
            List<INode> nodes, String expectedAsString, String expectedOid) {
        assertThat(nodes).hasSize(1);
        INode n = nodes.get(0);
        assertThat(n).isInstanceOf(RSA.class);
        assertThat(n.getKind()).isEqualTo(Signature.class);
        assertThat(n.asString()).isEqualTo(expectedAsString);
        INode oid = n.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo(expectedOid);
    }
}
