/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.plugin.rules.detection.openssl.keyagreement;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.INode;
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

/** A KDF selected through the EVP_PKEY interface gets the digest that is set on its context. */
class OpenSSLKeyAgreementKdfTest extends TestBase {

    private final List<String> assets = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/keyagreement/OpenSSLKeyAgreementKdfTestFile.cc", this);
        assertThat(assets)
                .containsExactly(
                        "KeyDerivationFunction:ANSI-KDF-X9.63 [MessageDigest:SHA-256]",
                        "MessageDigest:SHA-256",
                        "KeyDerivationFunction:ANSI-KDF-X9.42-SHA-384-ASN1 [MessageDigest:SHA-384]",
                        "MessageDigest:SHA-384",
                        "KeyEncapsulationMechanism:RSA",
                        "KeyEncapsulationMechanism:ML-KEM-768",
                        "KeyEncapsulationMechanism:DHKEM [KeyAgreement:x25519 [EllipticCurve:Curve25519]]",
                        "KeyEncapsulationMechanism:DHKEM [KeyAgreement:ECDH]",
                        "PublicKeyEncryption:HPKE [AuthenticatedEncryption:AES-128-GCM, KeyDerivationFunction:HKDF-SHA-256 [MessageDigest:SHA-256], KeyEncapsulationMechanism:DHKEM [KeyAgreement:x25519 [EllipticCurve:Curve25519]]]",
                        "PublicKeyEncryption:HPKE [AuthenticatedEncryption:ChaCha20-Poly1305 [MessageDigest:Poly1305], KeyDerivationFunction:HKDF-SHA-384 [MessageDigest:SHA-384], KeyEncapsulationMechanism:DHKEM [KeyAgreement:ECDH [EllipticCurve:secp384r1]]]",
                        "PublicKeyEncryption:HPKE [AuthenticatedEncryption:AES-128-GCM, KeyDerivationFunction:HKDF-SHA-256 [MessageDigest:SHA-256], KeyEncapsulationMechanism:DHKEM [KeyAgreement:x25519 [EllipticCurve:Curve25519]]]",
                        "PublicKeyEncryption:HPKE [AuthenticatedEncryption:AES-256-GCM, KeyDerivationFunction:HKDF-SHA-256 [MessageDigest:SHA-256], KeyEncapsulationMechanism:DHKEM [KeyAgreement:ECDH [EllipticCurve:secp256r1]]]");
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
     * The kind and name of the node, followed by the description of each algorithm and curve child.
     */
    @Nonnull
    private static String describe(@Nonnull INode node) {
        final String children =
                node.getChildren().values().stream()
                        .filter(
                                child ->
                                        child instanceof IAlgorithm
                                                || child instanceof EllipticCurve)
                        .map(OpenSSLKeyAgreementKdfTest::describe)
                        .sorted()
                        .collect(Collectors.joining(", "));
        final String self = node.getKind().getSimpleName() + ":" + node.asString();
        return children.isEmpty() ? self : self + " [" + children + "]";
    }
}
