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
package com.ibm.plugin.rules.detection.openssl.legacy;

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
 * Covers the rules in {@link OpenSSLLegacyMac}. The digest passed to {@code HMAC_Init_ex}, {@code
 * HMAC_Init} or {@code HMAC}, and the cipher passed to {@code CMAC_Init}, are traced back to the
 * call that created them and attached to the MAC, which reports them.
 */
class OpenSSLLegacyMacTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 21: HMAC_Init_ex(hctx, key, 32, md1, NULL);
                    finding(
                            "MacContext{ValueAction:HMAC}[DigestContext{ValueAction:SHA-256}]",
                            "Mac:HMAC-SHA-256[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], Oid:1.2.840.113549.2.9, "
                                    + "Tag:TAG]"),
                    // 23: HMAC_Init(hctx, key, 32, md2);
                    finding(
                            "MacContext{ValueAction:HMAC}[DigestContext{ValueAction:SHA-256}]",
                            "Mac:HMAC-SHA-256[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], Oid:1.2.840.113549.2.9, "
                                    + "Tag:TAG]"),
                    // 27: HMAC(md3, key, 32, data, 64, out, &outlen);
                    finding(
                            "MacContext{ValueAction:HMAC}[DigestContext{ValueAction:SHA-256}]",
                            "Mac:HMAC-SHA-256[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], Oid:1.2.840.113549.2.9, "
                                    + "Tag:TAG]"),
                    // 32: CMAC_Init(cctx, key, 32, cmac_cipher, NULL);
                    finding(
                            "MacContext{ValueAction:CMAC}[CipherContext{ValueAction:AES-128-CBC}]",
                            "Mac:CMAC-AES[BlockCipher:AES-128-CBC[BlockSize:128, KeyLength:128, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.2], Tag:TAG]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/legacy/OpenSSLLegacyMacTestFile.cc", this);
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
