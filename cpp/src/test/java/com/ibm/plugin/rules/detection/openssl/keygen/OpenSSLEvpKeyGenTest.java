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
package com.ibm.plugin.rules.detection.openssl.keygen;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/** Covers the rules of {@link OpenSSLEvpKeyGen} and its per-algorithm context rules. */
class OpenSSLEvpKeyGenTest extends TestBase {

    private final List<String> assets = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/keygen/OpenSSLEvpKeyGenTestFile.cc", this);
        assertThat(assets)
                .containsExactly(
                        // DSA parameters with their digest, generated
                        "DSA-2048-SHA-256[2.16.840.1.101.3.4.3.2, 2048, SHA-256]",
                        // the EVP_sha256() call is also reported on its own
                        "SHA-256[2.16.840.1.101.3.4.2.1, 256, 512, DIGEST]",
                        "DSA-SHA-256[2.16.840.1.101.3.4.3.2, SHA-256]",
                        "EC-secp256r1[1.2.840.10045.2.1, secp256r1]",
                        "EC-secp256r1[1.2.840.10045.2.1, secp256r1]",
                        "EC-secp192r1[1.2.840.10045.2.1, secp192r1]",
                        "EC-secp224r1[1.2.840.10045.2.1, secp224r1]",
                        "private key RSA-2048[1.2.840.113549.1.1.1, 2048, KEYGENERATION]",
                        "private key RSA-2048[1.2.840.113549.1.1.1, 2048, KEYGENERATION]",
                        "ML-KEM-768[2.16.840.1.101.3.4.4.2, 768]");
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
        for (INode node : nodes) {
            // a generated key is described by its algorithm
            final boolean privateKey = node instanceof PrivateKey;
            final INode described = privateKey ? algorithmOf(node) : node;
            assets.add(
                    (privateKey ? "private key " : "")
                            + described.asString()
                            + described.getChildren().values().stream()
                                    .map(INode::asString)
                                    .sorted()
                                    .toList());
        }
    }

    @Nonnull
    private static INode algorithmOf(@Nonnull INode key) {
        return key.getChildren().values().stream()
                .filter(IAlgorithm.class::isInstance)
                .findFirst()
                .orElseThrow();
    }
}
