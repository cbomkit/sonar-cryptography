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
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.functionality.KeyGeneration;
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

/**
 * The key type is selected when the key generation context is created, and the size or curve set on
 * that context belongs to it; {@code EVP_PKEY_Q_keygen} takes both in one call.
 */
class OpenSSLEvpKeyGenContextTest extends TestBase {

    private final List<String> keys = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/keygen/OpenSSLEvpKeyGenContextTestFile.cc", this);
        assertThat(keys)
                .containsExactly(
                        "private key RSA-3072[1.2.840.113549.1.1.1, 3072] generated",
                        "private key EC-secp384r1[1.2.840.10045.2.1, secp384r1] generated",
                        "FFDH-2048[1.2.840.113549.1.3.1, 2048]",
                        "FFDH-3072[1.2.840.113549.1.3.1, 3072]",
                        "FFDH-1024[1.2.840.113549.1.3.1, 1024]",
                        // RSA-PSS key: size, digest and salt length (in bits)
                        "RSA-PSS[1.2.840.113549.1.1.10, 2048, 256, SHA-256]",
                        "private key RSA-4096[1.2.840.113549.1.1.1, 4096] generated",
                        "private key EC-secp256r1[1.2.840.10045.2.1, secp256r1] generated",
                        "private key x25519[1.3.101.110, Curve25519] generated");
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
        if (!(detectionStore.getDetectionValueContext() instanceof KeyContext)) {
            // the EVP_sha256() call is also reported on its own
            return;
        }
        assertThat(nodes).hasSize(1);
        // a generated key is described by its algorithm
        final boolean privateKey = nodes.get(0) instanceof PrivateKey;
        INode key = privateKey ? algorithmOf(nodes.get(0)) : nodes.get(0);
        keys.add(
                (privateKey ? "private key " : "")
                        + key.asString()
                        + key.getChildren().values().stream()
                                .filter(child -> !(child instanceof KeyGeneration))
                                .map(INode::asString)
                                .sorted()
                                .toList()
                        + (key.hasChildOfType(KeyGeneration.class).isPresent()
                                ? " generated"
                                : ""));
    }

    @Nonnull
    private static INode algorithmOf(@Nonnull INode key) {
        return key.getChildren().values().stream()
                .filter(IAlgorithm.class::isInstance)
                .findFirst()
                .orElseThrow();
    }
}
