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
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.functionality.Functionality;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * The legacy RSA operations report RSA with the scheme selected by their padding argument:
 * encryption and decryption with the public and private key, and the signature primitive with the
 * private key (RSA_private_encrypt) and its verification (RSA_public_decrypt).
 */
class OpenSSLLegacyRsaOperationTest extends TestBase {

    private final List<String> assets = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/legacy/OpenSSLLegacyRsaOperationTestFile.cc", this);
        assertThat(assets)
                .containsExactly(
                        "PublicKeyEncryption:RSA-OAEP [Encrypt:ENCRYPT, Padding:OAEP]",
                        "PublicKeyEncryption:RSA [Decrypt:DECRYPT, Padding:PKCS1]",
                        "PublicKeyEncryption:RSA [Encrypt:ENCRYPT]",
                        "Signature:RSA-PKCS1-1.5 [Padding:PKCS1, Sign:SIGN]",
                        "Signature:ANSI X9.31 [Verify:VERIFY]");
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
        nodes.forEach(node -> assets.add(describe(node)));
    }

    /**
     * The kind and name of the node, followed by the description of each key, algorithm, curve, key
     * length and operation child.
     */
    @Nonnull
    private static String describe(@Nonnull INode node) {
        final String children =
                node.getChildren().values().stream()
                        .filter(
                                child ->
                                        child instanceof Key
                                                || child instanceof IAlgorithm
                                                || child instanceof EllipticCurve
                                                || child instanceof KeyLength
                                                || child instanceof Functionality
                                                || child instanceof Padding)
                        .map(OpenSSLLegacyRsaOperationTest::describe)
                        .sorted()
                        .collect(Collectors.joining(", "));
        final String self = node.getKind().getSimpleName() + ":" + node.asString();
        return children.isEmpty() ? self : self + " [" + children + "]";
    }
}
