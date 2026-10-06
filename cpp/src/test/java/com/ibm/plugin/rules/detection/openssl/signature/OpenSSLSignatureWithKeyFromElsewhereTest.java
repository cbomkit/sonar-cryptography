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

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.plugin.CxxAggregator;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.rules.CxxInventoryRule;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * A signature made with a key that is not generated in the analyzed code, e.g. a key loaded from a
 * file or a PKCS#12 container, or given to the function, is reported as a signature with the digest
 * it uses. The signature scheme depends on the type of the key, which is not known, unless a
 * setting of the operation names it, e.g. the RSA-PSS padding. A certificate signed with {@code
 * X509_sign_ctx} is reported by the initialization of its signing context.
 */
class OpenSSLSignatureWithKeyFromElsewhereTest {

    @AfterEach
    void resetSharedState() {
        CxxAggregator.reset();
    }

    @Test
    void test() {
        CxxVerifier.verifyFiles(
                List.of(
                        "rules/detection/openssl/signature/OpenSSLSignatureWithKeyFromElsewhereTestFile.cc"),
                new CxxInventoryRule());

        assertThat(CxxAggregator.getDetectedNodes())
                .extracting(OpenSSLSignatureWithKeyFromElsewhereTest::describe)
                .containsExactly(
                        "Signature:SIGN:SHA-256",
                        "Signature:VERIFY:SHA-384",
                        "ProbabilisticSignatureScheme:RSA-PSS:SIGN:SHA-256",
                        "Signature:SIGN:SHA-256",
                        "Signature:SIGN:SHA-1",
                        "Signature:SIGN:SHA-512",
                        "Signature:SIGN:SHA-1",
                        "Signature:SIGN:",
                        "Signature:SIGN:",
                        "Signature:SIGN:SHA-384",
                        "Signature:SIGN:SHA-512",
                        "Signature:SIGN:SHA-224");
    }

    /**
     * The kind of a node, the RSA-PSS scheme when it is one, its operation and the digest it uses.
     */
    @Nonnull
    private static String describe(@Nonnull INode node) {
        final String kind = node.is(Signature.class) ? "Signature" : node.getKind().getSimpleName();
        final String scheme = "RSA-PSS".equals(node.asString()) ? "RSA-PSS:" : "";
        final String operation =
                node.hasChildOfType(Sign.class).isPresent()
                        ? "SIGN"
                        : node.hasChildOfType(Verify.class).isPresent() ? "VERIFY" : "";
        final Optional<INode> digest = node.hasChildOfType(MessageDigest.class);
        return kind + ":" + scheme + operation + ":" + digest.map(INode::asString).orElse("");
    }
}
