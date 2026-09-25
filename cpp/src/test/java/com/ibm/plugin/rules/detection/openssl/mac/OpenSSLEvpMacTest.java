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
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.KMAC;
import com.ibm.mapper.model.algorithms.Poly1305;
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
 * Covers all rule entries in {@link OpenSSLEvpMac}.
 *
 * <p>{@code EVP_MAC_fetch(lib, "HMAC"/"CMAC"/"GMAC", props)} raises one finding per MAC family (the
 * real fetched name) rather than guessing a digest/cipher that isn't visible at the fetch call
 * site. The real digest (HMAC) or cipher (CMAC/GMAC), when the code sets one via {@code
 * EVP_MAC_CTX_set_params(ctx, params)}, is a separate, independently traced finding: {@code params}
 * is resolved back to its {@code OSSL_PARAM params[] = {...}} declaration (see {@link
 * com.ibm.engine.language.cxx.CxxSemantic#resolveValues}), and {@link
 * com.ibm.plugin.rules.detection.openssl.kdf.OpenSSLParamsScannerFactory} scans that array for the
 * {@code "digest"}/{@code "cipher"}-keyed entry.
 *
 * <p>Follows the deep-assert pattern documented in {@link
 * com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRandTest}.
 */
class OpenSSLEvpMacTest extends TestBase {

    private final Set<String> observedMac = new HashSet<>();
    private final Set<String> observedDigest = new HashSet<>();
    private final Set<String> observedCipher = new HashSet<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/mac/OpenSSLEvpMacTestFile.cc", this);
        assertThat(observedMac).hasSize(11);
        assertThat(observedDigest).containsExactly("SHA-256");
        assertThat(observedCipher).containsExactly("AES-128-CBC");
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

        // EVP_MAC_CTX_set_params("digest", "SHA256") and legacy HMAC()/HMAC_Init_ex()'s real
        // digest: resolved via OpenSSLParamsScannerFactory / OpenSSLEvpMessageDigest, separate
        // from the HMAC fetch/family finding.
        if (detectionStore.getDetectionValueContext() instanceof DigestContext) {
            observedDigest.add(value.asString());
            assertThat(value.asString()).isEqualTo("SHA-256");
            INode n = head(nodes);
            assertThat(n).isInstanceOf(MessageDigest.class);
            return;
        }

        // Legacy CMAC_Init()'s real cipher: resolved via OpenSSLEvpCipher, separate from the
        // "CMAC" family finding.
        if (detectionStore.getDetectionValueContext() instanceof CipherContext) {
            observedCipher.add(value.asString());
            assertThat(value.asString()).isEqualTo("AES-128-CBC");
            INode n = head(nodes);
            assertThat(n).isInstanceOf(AES.class);
            assertThat(n.asString()).isEqualTo("AES-128-CBC");
            return;
        }

        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(MacContext.class);
        String v = value.asString();
        observedMac.add(v);

        switch (v) {
            // EVP_MAC_CTX_set_params("cipher", "AES-128-CBC"): real cipher resolved via
            // OpenSSLParamsScannerFactory, separate from the CMAC fetch finding.
            case "CMAC-AES-128" -> {
                INode n = head(nodes);
                assertThat(n.getKind()).isEqualTo(Mac.class);
                assertThat(n.asString()).isEqualTo("CMAC-AES");
                INode aes = n.getChildren().get(BlockCipher.class);
                assertThat(aes).isNotNull().isInstanceOf(AES.class);
                assertThat(aes.asString()).isEqualTo("AES-128");
            }
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
                assertThat(n.asString()).isEqualTo("BLAKE2b-512");
            }
            case "BLAKE2SMAC" -> {
                INode n = head(nodes);
                assertThat(n).isInstanceOf(BLAKE2s.class);
                assertThat(n.asString()).isEqualTo("BLAKE2s-256");
            }
            // EVP_MAC_fetch's bare family findings carry no children (no digest/cipher visible
            // at the fetch call site). HMAC()/HMAC_Init_ex()'s traced digest and CMAC_Init()'s
            // traced cipher nest as a child under their own "HMAC"/"CMAC" MacContext finding;
            // calls without one (the fetch findings) have no children at all.
            case "HMAC" ->
                    assertThat(nodes)
                            .allSatisfy(n -> assertThat(n).isInstanceOf(MessageDigest.class));
            case "CMAC" -> assertThat(nodes).allSatisfy(n -> assertThat(n).isInstanceOf(AES.class));
            case "GMAC" -> assertThat(nodes).isEmpty();
            default -> throw new AssertionError("Unexpected value: " + v);
        }
    }

    /* helpers */

    private static INode head(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        return nodes.get(0);
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
