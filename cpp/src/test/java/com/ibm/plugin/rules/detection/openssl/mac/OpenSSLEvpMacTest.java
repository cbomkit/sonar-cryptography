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
package com.ibm.plugin.rules.detection.openssl.mac;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.Aria;
import com.ibm.mapper.model.algorithms.CMAC;
import com.ibm.mapper.model.algorithms.Camellia;
import com.ibm.mapper.model.algorithms.DESede;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.KMAC;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.Poly1305;
import com.ibm.mapper.model.algorithms.RIPEMD;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.SM3;
import com.ibm.mapper.model.algorithms.SM4;
import com.ibm.mapper.model.algorithms.SipHash;
import com.ibm.mapper.model.algorithms.blake.BLAKE2b;
import com.ibm.mapper.model.algorithms.blake.BLAKE2s;
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
 * Covers all 42 rule entries in {@link OpenSSLEvpMac}.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 */
class OpenSSLEvpMacTest extends TestBase {

    private final Set<String> observed = new HashSet<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/mac/OpenSSLEvpMacTestFile.cc", this);
        assertThat(observed).hasSize(40);
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
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(MacContext.class);
        IValue<AstNode> value = detectionStore.getDetectionValues().get(0);
        observed.add(value.asString());

        String v = value.asString();
        switch (v) {
            case "HMAC-MD5" -> assertHmac(nodes, MD5.class, "MD5", "HMAC-MD5", 128);
            case "HMAC-SHA1" -> assertHmac(nodes, SHA.class, "SHA1", "HMAC-SHA1", 160);
            case "HMAC-SHA224" -> assertHmacSha2(nodes, 224);
            case "HMAC-SHA256" -> assertHmacSha2(nodes, 256);
            case "HMAC-SHA384" -> assertHmacSha2(nodes, 384);
            case "HMAC-SHA512" -> assertHmacSha2(nodes, 512);
            // SHA-512/224 + SHA-512/256 → translator emits HMAC-SHA224 / HMAC-SHA256
            case "HMAC-SHA512/224" -> assertHmacSha2(nodes, 224);
            case "HMAC-SHA512/256" -> assertHmacSha2(nodes, 256);
            case "HMAC-SHA3-224" -> assertHmacSha3(nodes, 224);
            case "HMAC-SHA3-256" -> assertHmacSha3(nodes, 256);
            case "HMAC-SHA3-384" -> assertHmacSha3(nodes, 384);
            case "HMAC-SHA3-512" -> assertHmacSha3(nodes, 512);
            case "HMAC-RIPEMD160" ->
                    assertHmac(nodes, RIPEMD.class, "RIPEMD-160", "HMAC-RIPEMD", 160);
            case "HMAC-BLAKE2B" -> assertHmac(nodes, BLAKE2b.class, "BLAKE2b", "HMAC-BLAKE2b", 512);
            case "HMAC-BLAKE2S" -> assertHmac(nodes, BLAKE2s.class, "BLAKE2s", "HMAC-BLAKE2s", 256);
            case "HMAC-SM3" -> assertHmac(nodes, SM3.class, "SM3", "HMAC-SM3", 256);
            case "CMAC-AES-128" -> assertCmacAes(nodes, 128);
            case "CMAC-AES-192" -> assertCmacAes(nodes, 192);
            case "CMAC-AES-256" -> assertCmacAes(nodes, 256);
            case "CMAC-3DES" -> assertCmacDesede(nodes);
            case "CMAC-CAMELLIA-128" -> assertCmacCamellia(nodes, 128);
            case "CMAC-CAMELLIA-192" -> assertCmacCamellia(nodes, 192);
            case "CMAC-CAMELLIA-256" -> assertCmacCamellia(nodes, 256);
            case "CMAC-ARIA-128" -> assertCmacAria(nodes, 128);
            case "CMAC-ARIA-192" -> assertCmacAria(nodes, 192);
            case "CMAC-ARIA-256" -> assertCmacAria(nodes, 256);
            case "CMAC-SM4" -> assertCmacSm4(nodes);
            case "GMAC-AES-128" -> assertGmacAes(nodes, 128);
            case "GMAC-AES-192" -> assertGmacAes(nodes, 192);
            case "GMAC-AES-256" -> assertGmacAes(nodes, 256);
            case "POLY1305" -> {
                INode n = head(nodes);
                assertThat(n).isInstanceOf(Poly1305.class);
                assertThat(n.asString()).isEqualTo("Poly1305");
            }
            case "SIPHASH-2-4", "SIPHASH-4-8" -> assertSipHash(nodes);
            case "KMAC128" -> assertKmac(nodes, "KMAC128", 256);
            case "KMAC256" -> assertKmac(nodes, "KMAC256", 512);
            case "BLAKE2BMAC" -> {
                INode n = head(nodes);
                assertThat(n).isInstanceOf(BLAKE2b.class);
                assertThat(n.asString()).isEqualTo("BLAKE2b");
            }
            case "BLAKE2SMAC" -> {
                INode n = head(nodes);
                assertThat(n).isInstanceOf(BLAKE2s.class);
                assertThat(n.asString()).isEqualTo("BLAKE2s");
            }
            case "MAC" -> assertThat(nodes).isEmpty();
            case "HMAC", "CMAC" -> assertThat(nodes).isNotNull();
            default -> throw new AssertionError("Unexpected value: " + v);
        }
    }

    /* helpers */

    private static INode head(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        return nodes.get(0);
    }

    private static void assertHmac(
            List<INode> nodes,
            Class<? extends INode> digestClass,
            String digestAsString,
            String macAsString,
            int digestSize) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(HMAC.class);
        assertThat(n.getKind()).isEqualTo(Mac.class);
        assertThat(n.asString()).isEqualTo(macAsString);
        INode digest = n.getChildren().get(MessageDigest.class);
        assertThat(digest).isNotNull().isInstanceOf(digestClass);
        assertThat(digest.asString()).isEqualTo(digestAsString);
        INode size = digest.getChildren().get(DigestSize.class);
        assertThat(size).isNotNull();
        assertThat(size.asString()).isEqualTo(Integer.toString(digestSize));
    }

    private static void assertHmacSha2(List<INode> nodes, int digestSize) {
        assertHmac(nodes, SHA2.class, "SHA" + digestSize, "HMAC-SHA" + digestSize, digestSize);
    }

    private static void assertHmacSha3(List<INode> nodes, int digestSize) {
        assertHmac(nodes, SHA3.class, "SHA3-" + digestSize, "HMAC-SHA3-" + digestSize, digestSize);
    }

    private static void assertCmacAes(List<INode> nodes, int keyLength) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(CMAC.class);
        assertThat(n.getKind()).isEqualTo(Mac.class);
        assertThat(n.asString()).isEqualTo("AES-CMAC");
        INode aes = n.getChildren().get(BlockCipher.class);
        assertThat(aes).isNotNull().isInstanceOf(AES.class);
        assertThat(aes.asString()).isEqualTo("AES" + keyLength);
        INode kl = aes.getChildren().get(KeyLength.class);
        assertThat(kl).isNotNull();
        assertThat(kl.asString()).isEqualTo(Integer.toString(keyLength));
    }

    private static void assertCmacDesede(List<INode> nodes) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(CMAC.class);
        assertThat(n.asString()).isEqualTo("DESede-CMAC");
        INode des = n.getChildren().get(BlockCipher.class);
        assertThat(des).isNotNull().isInstanceOf(DESede.class);
        assertThat(des.asString()).isEqualTo("DESede168");
    }

    private static void assertCmacCamellia(List<INode> nodes, int keyLength) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(CMAC.class);
        assertThat(n.asString()).isEqualTo("Camellia-CMAC");
        INode cam = n.getChildren().get(BlockCipher.class);
        assertThat(cam).isNotNull().isInstanceOf(Camellia.class);
        INode kl = cam.getChildren().get(KeyLength.class);
        assertThat(kl).isNotNull();
        assertThat(kl.asString()).isEqualTo(Integer.toString(keyLength));
    }

    private static void assertCmacAria(List<INode> nodes, int keyLength) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(CMAC.class);
        assertThat(n.asString()).isEqualTo("Aria-CMAC");
        INode aria = n.getChildren().get(BlockCipher.class);
        assertThat(aria).isNotNull().isInstanceOf(Aria.class);
        INode kl = aria.getChildren().get(KeyLength.class);
        assertThat(kl).isNotNull();
        assertThat(kl.asString()).isEqualTo(Integer.toString(keyLength));
    }

    private static void assertCmacSm4(List<INode> nodes) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(CMAC.class);
        assertThat(n.asString()).isEqualTo("SM4-CMAC");
        INode sm4 = n.getChildren().get(BlockCipher.class);
        assertThat(sm4).isNotNull().isInstanceOf(SM4.class);
    }

    private static void assertGmacAes(List<INode> nodes, int keyLength) {
        INode n = head(nodes);
        assertThat(n.getKind()).isEqualTo(Mac.class);
        assertThat(n.asString()).isEqualTo("GMAC");
        INode aes = n.getChildren().get(BlockCipher.class);
        assertThat(aes).isNotNull().isInstanceOf(AES.class);
        assertThat(aes.asString()).isEqualTo("AES" + keyLength);
        INode kl = aes.getChildren().get(KeyLength.class);
        assertThat(kl).isNotNull();
        assertThat(kl.asString()).isEqualTo(Integer.toString(keyLength));
    }

    private static void assertSipHash(List<INode> nodes) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(SipHash.class);
        assertThat(n.getKind()).isEqualTo(Mac.class);
        assertThat(n.asString()).isEqualTo("SipHash");
        INode kl = n.getChildren().get(KeyLength.class);
        assertThat(kl).isNotNull();
        assertThat(kl.asString()).isEqualTo("128");
        INode size = n.getChildren().get(DigestSize.class);
        assertThat(size).isNotNull();
        assertThat(size.asString()).isEqualTo("64");
    }

    private static void assertKmac(List<INode> nodes, String asString, int digestSize) {
        INode n = head(nodes);
        assertThat(n).isInstanceOf(KMAC.class);
        assertThat(n.getKind()).isEqualTo(Mac.class);
        assertThat(n.asString()).isEqualTo(asString);
        INode size = n.getChildren().get(DigestSize.class);
        assertThat(size).isNotNull();
        assertThat(size.asString()).isEqualTo(Integer.toString(digestSize));
    }
}
