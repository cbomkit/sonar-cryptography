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
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.KMAC;
import com.ibm.mapper.model.algorithms.SipHash;
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

    private final List<String> macs = new ArrayList<>();
    private final List<String> digests = new ArrayList<>();
    private final List<String> ciphers = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/mac/OpenSSLEvpMacTestFile.cc", this);
        assertThat(macs)
                .containsExactly(
                        "HMAC",
                        "CMAC",
                        "GMAC",
                        "Poly1305",
                        "SipHash",
                        "KMAC128",
                        "KMAC256",
                        "BLAKE2b-512",
                        "BLAKE2s-256",
                        "HMAC",
                        "HMAC-SHA-256",
                        "HMAC-SHA-256",
                        "CMAC-AES");
        // the EVP_sha256()/EVP_aes_128_cbc() calls are also reported on their own
        assertThat(digests).containsExactly("SHA-256", "SHA-256");
        assertThat(ciphers).containsExactly("AES-128-CBC");
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
        assertThat(nodes).hasSize(1);
        INode n = nodes.get(0);
        if (detectionStore.getDetectionValueContext() instanceof DigestContext) {
            assertThat(n).isInstanceOf(MessageDigest.class);
            digests.add(n.asString());
            return;
        }
        if (detectionStore.getDetectionValueContext() instanceof CipherContext) {
            assertThat(n).isInstanceOf(AES.class);
            ciphers.add(n.asString());
            return;
        }
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(MacContext.class);
        assertThat(n.getKind()).isEqualTo(Mac.class);
        if (n instanceof SipHash) {
            assertThat(n.getChildren().get(KeyLength.class).asString()).isEqualTo("128");
            assertThat(n.getChildren().get(DigestSize.class).asString()).isEqualTo("64");
        } else if (n instanceof KMAC) {
            assertThat(n.getChildren().get(DigestSize.class)).isNotNull();
        }
        macs.add(n.asString());
    }
}
