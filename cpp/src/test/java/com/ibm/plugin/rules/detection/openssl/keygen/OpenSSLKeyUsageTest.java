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
 * The operations performed with a generated key are reported on that key, as the Python module
 * reports the signature or key exchange made with a private key: a signature, key agreement,
 * encryption or key encapsulation of the key's algorithm, with the digest or padding it uses.
 */
class OpenSSLKeyUsageTest extends TestBase {

    private final List<String> assets = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/keygen/OpenSSLKeyUsageTestFile.cc", this);
        assertThat(assets)
                .containsExactly(
                        "PrivateKey:EC [KeyGeneration:KEYGENERATION, Signature:ECDSA-secp256r1-SHA-256 [EllipticCurve:secp256r1, MessageDigest:SHA-256 [Digest:DIGEST], Sign:SIGN]]",
                        "MessageDigest:SHA-256 [Digest:DIGEST]",
                        "PrivateKey:RSA [KeyGeneration:KEYGENERATION, ProbabilisticSignatureScheme:RSA-PSS [KeyLength:3072, MessageDigest:SHA-384 [Digest:DIGEST], Verify:VERIFY]]",
                        "MessageDigest:SHA-384 [Digest:DIGEST]",
                        "ProbabilisticSignatureScheme:RSA-PSS",
                        "PrivateKey:x25519 [KeyAgreement:x25519 [EllipticCurve:Curve25519, KeyDerivation:KEYDERIVATION, KeyGeneration:KEYGENERATION]]",
                        "PrivateKey:EC [KeyAgreement:ECDH [EllipticCurve:secp384r1, KeyDerivation:KEYDERIVATION], KeyGeneration:KEYGENERATION]",
                        "PrivateKey:RSA [PublicKeyEncryption:RSA-OAEP [Encrypt:ENCRYPT, KeyGeneration:KEYGENERATION, KeyLength:2048, Padding:OAEP]]",
                        "PublicKeyEncryption:RSA-OAEP [Padding:OAEP]",
                        "PrivateKey:ML-KEM [KeyEncapsulationMechanism:ML-KEM-768 [Encapsulate:ENCAPSULATE, KeyGeneration:KEYGENERATION]]",
                        "PrivateKey:Ed25519 [Signature:Ed25519 [EllipticCurve:Edwards25519, KeyGeneration:KEYGENERATION, MessageDigest:SHA-512 [Digest:DIGEST], Sign:SIGN]]",
                        "MessageDigest:SHA-512 [Digest:DIGEST]",
                        "PrivateKey:RSA [PublicKeyEncryption:RSA-4096 [KeyGeneration:KEYGENERATION, KeyLength:4096]]",
                        "PrivateKey:FFDH [KeyAgreement:FFDH [KeyDerivation:KEYDERIVATION, KeyLength:2048], KeyGeneration:KEYGENERATION]",
                        "PrivateKey:RSA [KeyEncapsulationMechanism:RSA [Encapsulate:ENCAPSULATE, KeyLength:3072], KeyGeneration:KEYGENERATION]",
                        "PrivateKey:x25519 [KeyEncapsulationMechanism:DHKEM [Encapsulate:ENCAPSULATE, KeyAgreement:x25519 [EllipticCurve:Curve25519]], KeyGeneration:KEYGENERATION]");
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
                        .map(OpenSSLKeyUsageTest::describe)
                        .sorted()
                        .collect(Collectors.joining(", "));
        final String self = node.getKind().getSimpleName() + ":" + node.asString();
        return children.isEmpty() ? self : self + " [" + children + "]";
    }
}
