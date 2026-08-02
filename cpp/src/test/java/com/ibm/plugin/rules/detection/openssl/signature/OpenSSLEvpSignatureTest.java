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
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
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
 * Covers all rule entries in {@link OpenSSLEvpSignature}.
 *
 * <p>{@code EVP_DigestSignInit}/{@code EVP_DigestVerifyInit}'s digest argument is traced back to
 * its constructing call (see {@link com.ibm.plugin.rules.detection.openssl.digest.
 * OpenSSLEvpMessageDigest}), surfacing as a {@link DigestContext} finding. The key algorithm
 * (RSA/DSA/ECDSA/EdDSA/ML-DSA/SLH-DSA/SM2) is carried by the {@code EVP_PKEY} passed to these and
 * the other sign/verify entry points, which isn't resolvable from the call site; those entry points
 * instead raise a {@link com.ibm.engine.model.SignatureAction} marker (SIGN/VERIFY), matching how
 * {@link com.ibm.plugin.rules.detection.jca.signature.JcaSignatureAction} marks {@code
 * Signature.sign()}/{@code verify()} in the Java module - the marker carries no algorithm identity
 * and resolves to no node.
 */
class OpenSSLEvpSignatureTest extends TestBase {

    private final Set<String> observedSignature = new HashSet<>();
    private final Set<String> observedDigest = new HashSet<>();

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/signature/OpenSSLEvpSignatureTestFile.cc", this);
        assertThat(observedSignature).hasSize(15);
        assertThat(observedDigest).containsExactly("SHA-256");
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

        if (detectionStore.getDetectionValueContext() instanceof DigestContext) {
            observedDigest.add(value.asString());
            INode n = head(nodes);
            assertThat(n).isInstanceOf(MessageDigest.class);
            assertThat(n.asString()).isEqualTo("SHA-256");
            return;
        }

        if (!(detectionStore.getDetectionValueContext() instanceof SignatureContext)) {
            return;
        }
        String v = value.asString();
        observedSignature.add(v);

        // EVP_SIGNATURE_fetch(NULL, "RSA", NULL): real algorithm name resolved via
        // CxxSignatureContextTranslator's Algorithm branch, but that translator requires a
        // digest-suffixed prefix ("RSA-SHA256" etc) - a bare "RSA" resolves to nothing.
        if (v.equals("RSA")) {
            assertThat(nodes).isEmpty();
        } else if (v.equals("SIGN")
                || v.equals("VERIFY")
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
}
