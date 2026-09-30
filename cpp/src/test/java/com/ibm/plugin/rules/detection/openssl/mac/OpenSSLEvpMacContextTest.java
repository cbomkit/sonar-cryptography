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
 * A MAC fetched by name gets the digest or cipher that is set on the context created from it,
 * whether it is passed to {@code EVP_MAC_init} or to {@code EVP_MAC_CTX_set_params}. A GMAC becomes
 * its cipher as a MAC in GMAC mode.
 */
class OpenSSLEvpMacContextTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 5: EVP_MAC *mac = EVP_MAC_fetch(NULL, "hmac", NULL);
                    finding(
                            "MacContext{Algorithm:hmac}[MacContext{}[DigestContext{Algorithm:SHA-256}]]",
                            "Mac:HMAC-SHA-256[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], Oid:1.2.840.113549.2.9, "
                                    + "Tag:TAG]"),
                    // 15: EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
                    finding(
                            "MacContext{Algorithm:CMAC}[MacContext{}[CipherContext{Algorithm:aes-256-cbc}]]",
                            "Mac:CMAC-AES[BlockCipher:AES-256-CBC[BlockSize:128, KeyLength:256, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.42], Tag:TAG]"),
                    // 25: EVP_MAC_fetch(NULL, "Poly1305", NULL);
                    finding("MacContext{Algorithm:Poly1305}", "Mac:Poly1305[Tag:TAG]"),
                    // 26: EVP_MAC_fetch(NULL, "SipHash", NULL);
                    finding(
                            "MacContext{Algorithm:SipHash}",
                            "Mac:SipHash[DigestSize:64, KeyLength:128, Tag:TAG]"),
                    // 27: EVP_MAC_fetch(NULL, "KMAC-256", NULL);
                    finding(
                            "MacContext{Algorithm:KMAC-256}",
                            "Mac:KMAC256[DigestSize:512, "
                                    + "ExtendableOutputFunction:cSHAKE256[Digest:DIGEST, "
                                    + "ParameterSetIdentifier:256], ParameterSetIdentifier:256, Tag:TAG]"),
                    // 31: EVP_MAC *mac = EVP_MAC_fetch(NULL, "GMAC", NULL);
                    finding(
                            "MacContext{Algorithm:GMAC}[MacContext{}[CipherContext{Algorithm:aes-128-gcm}]]",
                            "Mac:AES-128-GMAC[BlockSize:128, KeyLength:128, Mode:GMAC,"
                                    + " Oid:2.16.840.1.101.3.4.1.9, Tag:TAG]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/mac/OpenSSLEvpMacContextTestFile.cc", this);
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
