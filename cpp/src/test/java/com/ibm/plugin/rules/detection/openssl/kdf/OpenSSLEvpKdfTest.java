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
package com.ibm.plugin.rules.detection.openssl.kdf;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.ANSIX942;
import com.ibm.mapper.model.algorithms.ANSIX963;
import com.ibm.mapper.model.algorithms.CMAC;
import com.ibm.mapper.model.algorithms.ConcatenationKDF;
import com.ibm.mapper.model.algorithms.HKDF;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.KDFCounter;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.Scrypt;
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
 * Covers all 61 rule entries in {@link OpenSSLEvpKdf}.
 *
 * <p>61 findings, 51 unique detection values. Dispatches on value string.
 */
class OpenSSLEvpKdfTest extends TestBase {

    private int findingCount = 0;
    private final Set<String> observed = new HashSet<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/kdf/OpenSSLEvpKdfTestFile.cc", this);
        assertThat(findingCount).isEqualTo(61);
        assertThat(observed).hasSize(51);
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
        assertThat(detectionStore.getDetectionValueContext())
                .isInstanceOf(KeyDerivationFunctionContext.class);
        IValue<AstNode> value = detectionStore.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(ValueAction.class);

        String v = value.asString();
        observed.add(v);
        findingCount++;

        if (v.equals("PBKDF2-HMAC-SHA1")) {
            assertPbkdf2WithSha(nodes, SHA.class, "SHA1", 160);
        } else if (v.equals("PBKDF2-HMAC-SHA256")) {
            assertPbkdf2WithSha2(nodes, 256);
        } else if (v.equals("PBKDF2-HMAC-SHA384")) {
            assertPbkdf2WithSha2(nodes, 384);
        } else if (v.equals("PBKDF2-HMAC-SHA512")) {
            assertPbkdf2WithSha2(nodes, 512);
        } else if (v.equals("PBKDF2-HMAC")) {
            assertSimpleAlgo(nodes, PBKDF2.class, "PBKDF2");
        } else if (v.equals("HKDF-SHA1")) {
            assertHkdfWithSha(nodes, SHA.class, "HKDF-SHA1", 160);
        } else if (v.equals("HKDF-SHA256")) {
            assertHkdfWithSha2(nodes, 256, "HKDF-SHA256");
        } else if (v.equals("HKDF-SHA384")) {
            assertHkdfWithSha2(nodes, 384, "HKDF-SHA384");
        } else if (v.equals("HKDF-SHA512")) {
            assertHkdfWithSha2(nodes, 512, "HKDF-SHA512");
        } else if (v.equals("HKDF-SHA3-256")) {
            assertHkdfWithSha(nodes, SHA3.class, "HKDF-SHA3-256", 256);
        } else if (v.equals("HKDF-MD")) {
            assertThat(nodes).isNotNull();
        } else if (v.equals("HKDF-MODE")) {
            assertThat(nodes).isNotNull();
        } else if (v.equals("SCRYPT")) {
            assertSimpleAlgo(nodes, Scrypt.class, "SCRYPT");
        } else if (v.equals("TLS1-PRF-MD5-SHA1")
                || v.equals("TLS1-PRF-SHA256")
                || v.equals("TLS1-PRF-SHA384")
                || v.equals("TLS1-PRF-SHA512")) {
            assertSimpleAlgo(nodes, PBKDF2.class, "PBKDF2");
        } else if (v.equals("TLS1-PRF-MD")) {
            assertThat(nodes).isNotNull();
        } else if (v.equals("TLS13-KDF-SHA256")) {
            assertHkdfWithSha2(nodes, 256, "HKDF-SHA256");
        } else if (v.equals("TLS13-KDF-SHA384")) {
            assertHkdfWithSha2(nodes, 384, "HKDF-SHA384");
        } else if (v.equals("TLS13-KDF-SHA512")) {
            assertHkdfWithSha2(nodes, 512, "HKDF-SHA512");
        } else if (v.equals("X963KDF-SHA1")) {
            assertX963WithSha(nodes, SHA.class, 160);
        } else if (v.equals("X963KDF-SHA224")) {
            assertX963WithSha2(nodes, 224);
        } else if (v.equals("X963KDF-SHA256")) {
            assertX963WithSha2(nodes, 256);
        } else if (v.equals("X963KDF-SHA384")) {
            assertX963WithSha2(nodes, 384);
        } else if (v.equals("X963KDF-SHA512")) {
            assertX963WithSha2(nodes, 512);
        } else if (v.equals("KBKDF-HMAC-SHA1")) {
            assertKbkdfHmac(nodes, SHA.class, "HMAC-SHA1", 160);
        } else if (v.equals("KBKDF-HMAC-SHA256")) {
            assertKbkdfHmacSha2(nodes, 256);
        } else if (v.equals("KBKDF-HMAC-SHA384")) {
            assertKbkdfHmacSha2(nodes, 384);
        } else if (v.equals("KBKDF-HMAC-SHA512")) {
            assertKbkdfHmacSha2(nodes, 512);
        } else if (v.equals("KBKDF-CMAC-AES128")) {
            assertKbkdfCmacAes(nodes, 128);
        } else if (v.equals("KBKDF-CMAC-AES256")) {
            assertKbkdfCmacAes(nodes, 256);
        } else if (v.equals("X942KDF-SHA1")
                || v.equals("X942KDF-SHA256")
                || v.equals("X942KDF-CONCAT")) {
            assertSimpleAlgo(nodes, ANSIX942.class, "ANSI X9.42");
        } else if (v.equals("SSKDF")) {
            assertSimpleAlgo(nodes, ConcatenationKDF.class, "ConcatenationKDF");
        } else if (v.equals("SSHKDF-SHA1") || v.equals("SSHKDF-SHA256")) {
            assertSimpleAlgo(nodes, PBKDF2.class, "PBKDF2");
        } else if (v.equals("KRB5KDF")) {
            assertGenericKdf(nodes, "KRB5KDF", KeyDerivationFunction.class);
        } else if (v.equals("ARGON2D")) {
            assertGenericKdf(nodes, "Argon2d", PasswordBasedKeyDerivationFunction.class);
        } else if (v.equals("ARGON2I")) {
            assertGenericKdf(nodes, "Argon2i", PasswordBasedKeyDerivationFunction.class);
        } else if (v.equals("ARGON2ID")) {
            assertGenericKdf(nodes, "Argon2id", PasswordBasedKeyDerivationFunction.class);
        } else if (v.equals("PKCS12KDF")) {
            assertGenericKdf(nodes, "PKCS12KDF", PasswordBasedKeyDerivationFunction.class);
        } else if (v.equals("PVKKDF")) {
            assertGenericKdf(nodes, "PVKKDF", PasswordBasedKeyDerivationFunction.class);
        } else if (v.equals("HMAC-DRBG-KDF")) {
            assertGenericKdf(nodes, "HMAC-DRBG-KDF", KeyDerivationFunction.class);
        } else if (v.equals("KDF-CTX")) {
            assertThat(nodes).isNotNull();
        } else if (v.equals("PBE-KEYIVGEN")) {
            assertThat(nodes).isNotNull();
        } else if (v.equals("PKCS12")) {
            assertThat(nodes).isNotNull();
        } else if (v.equals("PKCS12-MAC")) {
            assertThat(nodes).isNotNull();
        } else if (v.equals("PKCS12-PBE")) {
            assertThat(nodes).isNotNull();
        } else if (v.equals("PKCS12-KDF")) {
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

    private static void assertSimpleAlgo(
            List<INode> nodes, Class<? extends INode> klass, String asString) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(klass);
        assertThat(n.asString()).isEqualTo(asString);
    }

    private static void assertGenericKdf(List<INode> nodes, String asString, Class<?> kindClass) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(Algorithm.class);
        assertThat(n.getKind()).isEqualTo(kindClass);
        assertThat(n.asString()).isEqualTo(asString);
    }

    private static void assertPbkdf2WithSha(
            List<INode> nodes, Class<? extends INode> shaClass, String shaName, int digestSize) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(PBKDF2.class);
        assertThat(n.asString()).isEqualTo("PBKDF2-" + shaName);
        INode digest = n.getChildren().get(MessageDigest.class);
        assertThat(digest).isNotNull().isInstanceOf(shaClass);
        assertThat(digest.asString()).isEqualTo(shaName);
        INode size = digest.getChildren().get(DigestSize.class);
        assertThat(size).isNotNull();
        assertThat(size.asString()).isEqualTo(Integer.toString(digestSize));
    }

    private static void assertPbkdf2WithSha2(List<INode> nodes, int digestSize) {
        assertPbkdf2WithSha(nodes, SHA2.class, "SHA" + digestSize, digestSize);
    }

    private static void assertHkdfWithSha(
            List<INode> nodes, Class<? extends INode> shaClass, String asString, int digestSize) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(HKDF.class);
        assertThat(n.asString()).isEqualTo(asString);
        INode digest = n.getChildren().get(MessageDigest.class);
        assertThat(digest).isNotNull().isInstanceOf(shaClass);
        INode size = digest.getChildren().get(DigestSize.class);
        assertThat(size).isNotNull();
        assertThat(size.asString()).isEqualTo(Integer.toString(digestSize));
    }

    private static void assertHkdfWithSha2(List<INode> nodes, int digestSize, String asString) {
        assertHkdfWithSha(nodes, SHA2.class, asString, digestSize);
    }

    private static void assertX963WithSha(
            List<INode> nodes, Class<? extends INode> shaClass, int digestSize) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(ANSIX963.class);
        assertThat(n.asString()).isEqualTo("ANSI X9.63");
        INode digest = n.getChildren().get(MessageDigest.class);
        assertThat(digest).isNotNull().isInstanceOf(shaClass);
        INode size = digest.getChildren().get(DigestSize.class);
        assertThat(size).isNotNull();
        assertThat(size.asString()).isEqualTo(Integer.toString(digestSize));
    }

    private static void assertX963WithSha2(List<INode> nodes, int digestSize) {
        assertX963WithSha(nodes, SHA2.class, digestSize);
    }

    private static void assertKbkdfHmac(
            List<INode> nodes,
            Class<? extends INode> shaClass,
            String hmacAsString,
            int digestSize) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(KDFCounter.class);
        assertThat(n.asString()).isEqualTo("KDF in Counter Mode");
        INode mac = n.getChildren().get(Mac.class);
        assertThat(mac).isNotNull().isInstanceOf(HMAC.class);
        assertThat(mac.asString()).isEqualTo(hmacAsString);
        INode digest = mac.getChildren().get(MessageDigest.class);
        assertThat(digest).isNotNull().isInstanceOf(shaClass);
        INode size = digest.getChildren().get(DigestSize.class);
        assertThat(size).isNotNull();
        assertThat(size.asString()).isEqualTo(Integer.toString(digestSize));
    }

    private static void assertKbkdfHmacSha2(List<INode> nodes, int digestSize) {
        assertKbkdfHmac(nodes, SHA2.class, "HMAC-SHA" + digestSize, digestSize);
    }

    private static void assertKbkdfCmacAes(List<INode> nodes, int keyLength) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(KDFCounter.class);
        assertThat(n.asString()).isEqualTo("KDF in Counter Mode");
        INode mac = n.getChildren().get(Mac.class);
        assertThat(mac).isNotNull().isInstanceOf(CMAC.class);
        assertThat(mac.asString()).isEqualTo("AES-CMAC");
        INode aes = mac.getChildren().get(BlockCipher.class);
        assertThat(aes).isNotNull().isInstanceOf(AES.class);
        assertThat(aes.asString()).isEqualTo("AES" + keyLength);
        INode keyLen = aes.getChildren().get(KeyLength.class);
        assertThat(keyLen).isNotNull();
        assertThat(keyLen.asString()).isEqualTo(Integer.toString(keyLength));
    }
}
