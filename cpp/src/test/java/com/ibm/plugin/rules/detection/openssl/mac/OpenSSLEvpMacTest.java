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

import static com.ibm.plugin.ExpectedFinding.assertAllReported;
import static com.ibm.plugin.ExpectedFinding.assertFinding;
import static com.ibm.plugin.ExpectedFinding.finding;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.ExpectedFinding;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
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
 * EVP_MAC_CTX_set_params(ctx, params)}, is detected from the {@code "digest"}/{@code "cipher"}
 * entry written to {@code params} (see {@link
 * com.ibm.plugin.rules.detection.openssl.params.OpenSSLParams}).
 */
class OpenSSLEvpMacTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 8: EVP_MAC_fetch(lib, "HMAC", props);
                    finding("MacContext{Algorithm:HMAC}", "Mac:HMAC[Tag:TAG]"),
                    // 9: EVP_MAC_fetch(lib, "CMAC", props);
                    finding("MacContext{Algorithm:CMAC}", "Mac:CMAC[Tag:TAG]"),
                    // 10: EVP_MAC_fetch(lib, "GMAC", props);
                    finding("MacContext{Algorithm:GMAC}", "Mac:GMAC[Tag:TAG]"),
                    // 11: EVP_MAC_fetch(lib, "Poly1305", props);
                    finding("MacContext{Algorithm:Poly1305}", "Mac:Poly1305[Tag:TAG]"),
                    // 12: EVP_MAC_fetch(lib, "SipHash", props);
                    finding(
                            "MacContext{Algorithm:SipHash}",
                            "Mac:SipHash[DigestSize:64, KeyLength:128, Tag:TAG]"),
                    // 13: EVP_MAC_fetch(lib, "KMAC128", props);
                    finding(
                            "MacContext{Algorithm:KMAC128}",
                            "Mac:KMAC128[DigestSize:256, "
                                    + "ExtendableOutputFunction:cSHAKE128[Digest:DIGEST, "
                                    + "ParameterSetIdentifier:128], ParameterSetIdentifier:128, "
                                    + "Tag:TAG]"),
                    // 14: EVP_MAC_fetch(lib, "KMAC256", props);
                    finding(
                            "MacContext{Algorithm:KMAC256}",
                            "Mac:KMAC256[DigestSize:512, "
                                    + "ExtendableOutputFunction:cSHAKE256[Digest:DIGEST, "
                                    + "ParameterSetIdentifier:256], ParameterSetIdentifier:256, "
                                    + "Tag:TAG]"),
                    // 15: EVP_MAC_fetch(lib, "BLAKE2BMAC", props);
                    finding(
                            "MacContext{Algorithm:BLAKE2BMAC}",
                            "Mac:BLAKE2b-512[DigestSize:512, SaltLength:128, Tag:TAG]"),
                    // 16: EVP_MAC_fetch(lib, "BLAKE2SMAC", props);
                    finding(
                            "MacContext{Algorithm:BLAKE2SMAC}",
                            "Mac:BLAKE2s-256[DigestSize:256, SaltLength:64, Tag:TAG]"),
                    // 18: EVP_Q_mac(lib, "HMAC", props, "SHA256", NULL, NULL, 0, NULL, 0, NULL, 0,
                    // NULL);
                    finding(
                            "MacContext{Algorithm:HMAC}[MacContext{AlgorithmParameter:SHA256}]",
                            "Mac:HMAC-SHA-256[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.113549.2.9, Tag:TAG]"),
                    // 19: EVP_Q_mac(lib, OSSL_MAC_NAME_CMAC, props, "AES-128-CBC", NULL, NULL, 0,
                    // NULL, 0, NULL, 0, NULL);
                    finding(
                            "MacContext{Algorithm:CMAC}[MacContext{AlgorithmParameter:AES-128-CBC}]",
                            "Mac:CMAC-AES[BlockCipher:AES-128-CBC[BlockSize:128, KeyLength:128, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.2], Tag:TAG]"),
                    // 24: HMAC(legacy_hmac_md, NULL, 0, NULL, 0, NULL, NULL);
                    finding(
                            "MacContext{ValueAction:HMAC}[DigestContext{ValueAction:SHA-256}]",
                            "Mac:HMAC-SHA-256[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.113549.2.9, Tag:TAG]"),
                    // 26: HMAC_Init_ex(NULL, NULL, 0, legacy_hmac_init_md, NULL);
                    finding(
                            "MacContext{ValueAction:HMAC}[DigestContext{ValueAction:SHA-256}]",
                            "Mac:HMAC-SHA-256[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.113549.2.9, Tag:TAG]"),
                    // 28: CMAC_Init(NULL, NULL, 0, legacy_cmac_cipher, NULL);
                    finding(
                            "MacContext{ValueAction:CMAC}[CipherContext{ValueAction:AES-128-CBC}]",
                            "Mac:CMAC-AES[BlockCipher:AES-128-CBC[BlockSize:128, KeyLength:128, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.2], Tag:TAG]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/mac/OpenSSLEvpMacTestFile.cc", this);
        assertAllReported(FINDINGS, findings);
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
        findings++;
        assertFinding(FINDINGS, findingId, detectionStore, nodes);
    }
}
