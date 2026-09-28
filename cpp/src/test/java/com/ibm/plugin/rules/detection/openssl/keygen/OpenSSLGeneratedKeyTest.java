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
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyLength;
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
 * A generated asymmetric key is reported as a private key holding its algorithm, as the Java and
 * Python modules report generated keys. Generated domain parameters are reported as the algorithm.
 */
class OpenSSLGeneratedKeyTest extends TestBase {

    private final List<String> assets = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/keygen/OpenSSLGeneratedKeyTestFile.cc", this);
        assertThat(assets)
                .containsExactly(
                        "PrivateKey:RSA [PublicKeyEncryption:RSA-3072 [KeyGeneration:KEYGENERATION, KeyLength:3072]]",
                        "PrivateKey:EC [PublicKeyEncryption:EC-secp256r1 [EllipticCurve:secp256r1, KeyGeneration:KEYGENERATION]]",
                        "PublicKeyEncryption:FFDH-2048 [KeyLength:2048]",
                        "PrivateKey:RSA [PublicKeyEncryption:RSA-2048 [KeyGeneration:KEYGENERATION, KeyLength:2048]]");
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
                                                || child instanceof Functionality)
                        .map(OpenSSLGeneratedKeyTest::describe)
                        .sorted()
                        .collect(Collectors.joining(", "));
        final String self = node.getKind().getSimpleName() + ":" + node.asString();
        return children.isEmpty() ? self : self + " [" + children + "]";
    }
}
