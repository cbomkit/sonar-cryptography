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
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
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
 * The signature algorithm fetched by name, the RSA-PSS salt length and the digests named for or
 * passed to a sign/verify operation are reported. The sign and verify calls themselves report
 * nothing: their signature algorithm is the type of the {@code EVP_PKEY}, which is not known at the
 * call.
 */
class OpenSSLEvpSignatureTest extends TestBase {

    private final Set<String> observedSignature = new HashSet<>();
    private final Set<String> observedDigest = new HashSet<>();
    private final Set<Integer> digestLines = new HashSet<>();

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/signature/OpenSSLEvpSignatureTestFile.cc", this);
        assertThat(observedSignature).containsExactlyInAnyOrder("RSA", "RSA-PSS");
        assertThat(observedDigest).containsExactly("SHA-256");
        // the mdname argument of EVP_DigestSignInit_ex / EVP_DigestVerifyInit_ex
        assertThat(digestLines).contains(17, 18);
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
            digestLines.add(value.getLocation().getTokenLine());
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

        switch (v) {
            // EVP_SIGNATURE_fetch(NULL, "RSA", NULL)
            case "RSA" -> {
                INode n = head(nodes);
                assertThat(n).isInstanceOf(RSA.class);
                assertThat(n.getKind()).isEqualTo(Signature.class);
            }
            // EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32)
            case "RSA-PSS" -> {
                INode n = head(nodes);
                assertThat(n).isInstanceOf(RSAssaPSS.class);
                assertThat(n.hasChildOfType(SaltLength.class)).map(INode::asString).contains("256");
            }
            default -> throw new AssertionError("Unexpected value: " + v);
        }
    }

    /* helpers */

    private static INode head(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        return nodes.get(0);
    }
}
