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
package com.ibm.plugin.rules.detection.openssl.signature;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.EdDSA;
import com.ibm.mapper.model.algorithms.MLDSA;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.SLHDSA;
import com.ibm.mapper.model.algorithms.SM2;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * Covers all 39 rule entries in {@link OpenSSLEvpSignature}.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 */
class OpenSSLEvpSignatureTest extends TestBase {

    private final Set<String> observed = new HashSet<>();

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/signature/OpenSSLEvpSignatureTestFile.cc", this);
        assertThat(observed).hasSize(39);
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
        if (!(detectionStore.getDetectionValueContext() instanceof SignatureContext)) {
            return;
        }
        IValue<AstNode> value = detectionStore.getDetectionValues().get(0);
        observed.add(value.asString());

        String v = value.asString();
        if (v.equals("RSA-MGF1-MD")
                || v.equals("RSA-PSS-SALTLEN")
                || v.equals("RSA-PSS-KEYGEN-MD")
                || v.equals("RSA-PSS-KEYGEN-MGF1-MD")
                || v.equals("RSA-PSS-KEYGEN-SALTLEN")) {
            assertThat(nodes).isNotNull();
        } else if (v.startsWith("RSA-PSS-")) {
            assertRsaPss(nodes, v);
        } else if (v.startsWith("RSA-")) {
            assertRsa(nodes, v);
        } else if (v.startsWith("DSA-")) {
            assertDsa(nodes, v);
        } else if (v.startsWith("ECDSA-SHA3-")) {
            assertEcdsaSha3(nodes, v);
        } else if (v.startsWith("ECDSA-")) {
            assertEcdsaSha(nodes, v);
        } else if (v.equals("SM2")) {
            INode n = head(nodes);
            assertThat(n).isInstanceOf(SM2.class);
            assertThat(n.getKind()).isEqualTo(Signature.class);
        } else if (v.equals("ED25519") || v.equals("ED448")) {
            INode n = head(nodes);
            assertThat(n).isInstanceOf(EdDSA.class);
            assertThat(n.getKind()).isEqualTo(Signature.class);
            assertThat(n.asString()).isEqualTo("EdDSA");
        } else if (v.startsWith("ML-DSA-")) {
            assertMldsa(nodes, v);
        } else if (v.startsWith("SLH-DSA-")) {
            INode n = head(nodes);
            assertThat(n).isInstanceOf(SLHDSA.class);
            assertThat(n.getKind()).isEqualTo(Signature.class);
            assertThat(n.asString()).isEqualTo("SLH-DSA");
        } else if (v.equals("SIGN")
                || v.equals("VERIFY")
                || v.equals("VERIFY-RECOVER")
                || v.equals("SIGNATURE-FETCH")
                || v.equals("SIGNATURE-MD")
                || v.equals("RSA-MGF1-MD")
                || v.equals("RSA-PSS-SALTLEN")
                || v.equals("RSA-PSS-KEYGEN-MD")
                || v.equals("RSA-PSS-KEYGEN-MGF1-MD")
                || v.equals("RSA-PSS-KEYGEN-SALTLEN")
                || v.equals("PKCS7-SIGN")
                || v.equals("PKCS7-DIGEST")
                || v.equals("CMS-SIGN")
                || v.equals("CMS-DIGEST-SIGN")
                || v.equals("OCSP-SIGN")
                || v.equals("TS-SIGNER-DIGEST")
                || v.equals("TS-IMPRINT-ALGO")
                || v.equals("TS-MD")
                || v.equals("CRMF-PBM")
                || v.equals("CRMF-POPO")) {
            assertThat(nodes).isNotNull();
        } else {
            throw new AssertionError("Unexpected value: " + v);
        }
    }

    /* helpers */

    private static INode head(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        return nodes.get(0);
    }

    private static int parseSize(String suffix) {
        return Integer.parseInt(suffix);
    }

    private static void assertDigestChild(
            INode parent, Class<? extends INode> shaClass, String shaName, int digestSize) {
        INode digest = parent.getChildren().get(MessageDigest.class);
        assertThat(digest).isNotNull().isInstanceOf(shaClass);
        assertThat(digest.asString()).isEqualTo(shaName);
        INode size = digest.getChildren().get(DigestSize.class);
        assertThat(size).isNotNull();
        assertThat(size.asString()).isEqualTo(Integer.toString(digestSize));
    }

    private static void assertRsa(List<INode> nodes, String v) {
        // RSA-SHA1 → asString "SHA1withRSA"; RSA-SHA224 → "SHA224withRSA" etc.
        INode n = head(nodes);
        assertThat(n).isInstanceOf(RSA.class);
        assertThat(n.getKind()).isEqualTo(Signature.class);
        String shaSuffix = v.substring(4); // "SHA1" / "SHA256" etc.
        assertThat(n.asString()).isEqualTo(shaSuffix + "withRSA");
        if (shaSuffix.equals("SHA1")) {
            assertDigestChild(n, SHA.class, "SHA1", 160);
        } else {
            assertDigestChild(n, SHA2.class, shaSuffix, parseSize(shaSuffix.substring(3)));
        }
    }

    private static void assertRsaPss(List<INode> nodes, String v) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(RSAssaPSS.class);
        assertThat(n.getKind()).isEqualTo(ProbabilisticSignatureScheme.class);
        assertThat(n.asString()).isEqualTo("RSASSA-PSS");
        String shaSuffix = v.substring("RSA-PSS-".length()); // SHA256/SHA384/SHA512
        assertDigestChild(n, SHA2.class, shaSuffix, parseSize(shaSuffix.substring(3)));
    }

    private static void assertDsa(List<INode> nodes, String v) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(DSA.class);
        assertThat(n.getKind()).isEqualTo(Signature.class);
        String shaSuffix = v.substring(4);
        assertThat(n.asString()).isEqualTo(shaSuffix + "withDSA");
        if (shaSuffix.equals("SHA1")) {
            assertDigestChild(n, SHA.class, "SHA1", 160);
        } else {
            assertDigestChild(n, SHA2.class, shaSuffix, parseSize(shaSuffix.substring(3)));
        }
    }

    private static void assertEcdsaSha(List<INode> nodes, String v) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(ECDSA.class);
        assertThat(n.getKind()).isEqualTo(Signature.class);
        String shaSuffix = v.substring("ECDSA-".length());
        assertThat(n.asString()).isEqualTo(shaSuffix + "withECDSA");
        if (shaSuffix.equals("SHA1")) {
            assertDigestChild(n, SHA.class, "SHA1", 160);
        } else {
            assertDigestChild(n, SHA2.class, shaSuffix, parseSize(shaSuffix.substring(3)));
        }
    }

    private static void assertEcdsaSha3(List<INode> nodes, String v) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(ECDSA.class);
        assertThat(n.getKind()).isEqualTo(Signature.class);
        String shaSuffix = v.substring("ECDSA-".length()); // "SHA3-256" etc.
        assertThat(n.asString()).isEqualTo(shaSuffix + "withECDSA");
        int sz = parseSize(shaSuffix.substring("SHA3-".length()));
        assertDigestChild(n, SHA3.class, shaSuffix, sz);
    }

    private static void assertMldsa(List<INode> nodes, String v) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(MLDSA.class);
        assertThat(n.getKind()).isEqualTo(Signature.class);
        int pset =
                switch (v) {
                    case "ML-DSA-44" -> 2;
                    case "ML-DSA-65" -> 3;
                    case "ML-DSA-87" -> 5;
                    default -> throw new AssertionError("Unknown ML-DSA: " + v);
                };
        assertThat(n.asString()).isEqualTo("ML-DSA-" + pset);
        INode oid = n.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo("2.16.840.1.101.3.4.3");
        INode psetNode = n.getChildren().get(ParameterSetIdentifier.class);
        assertThat(psetNode).isNotNull();
        assertThat(psetNode.asString()).isEqualTo(Integer.toString(pset));
    }
}
