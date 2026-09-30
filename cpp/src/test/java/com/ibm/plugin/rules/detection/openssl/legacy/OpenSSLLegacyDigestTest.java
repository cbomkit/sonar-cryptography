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

/** Covers all rule entries in {@link OpenSSLLegacyDigest}. */
class OpenSSLLegacyDigestTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 13: MD5_Init(&mc);
                    finding(
                            "DigestContext{ValueAction:MD5}",
                            "MessageDigest:MD5[BlockSize:512, Digest:DIGEST, DigestSize:128]"),
                    // 14: MD5(buf, 64, buf);
                    finding(
                            "DigestContext{ValueAction:MD5}",
                            "MessageDigest:MD5[BlockSize:512, Digest:DIGEST, DigestSize:128]"),
                    // 16: SHA1_Init(&s1);
                    finding(
                            "DigestContext{ValueAction:SHA-1}",
                            "MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, DigestSize:160, "
                                    + "Oid:1.3.14.3.2.26]"),
                    // 17: SHA1(buf, 64, buf);
                    finding(
                            "DigestContext{ValueAction:SHA-1}",
                            "MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, DigestSize:160, "
                                    + "Oid:1.3.14.3.2.26]"),
                    // 19: SHA224_Init(&s2);
                    finding(
                            "DigestContext{ValueAction:SHA-224}",
                            "MessageDigest:SHA-224[BlockSize:512, Digest:DIGEST, DigestSize:224, "
                                    + "Oid:2.16.840.1.101.3.4.2.4]"),
                    // 20: SHA224(buf, 64, buf);
                    finding(
                            "DigestContext{ValueAction:SHA-224}",
                            "MessageDigest:SHA-224[BlockSize:512, Digest:DIGEST, DigestSize:224, "
                                    + "Oid:2.16.840.1.101.3.4.2.4]"),
                    // 22: SHA256_Init(&s2);
                    finding(
                            "DigestContext{ValueAction:SHA-256}",
                            "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]"),
                    // 23: SHA256(buf, 64, buf);
                    finding(
                            "DigestContext{ValueAction:SHA-256}",
                            "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]"),
                    // 25: SHA384_Init(&s5);
                    finding(
                            "DigestContext{ValueAction:SHA-384}",
                            "MessageDigest:SHA-384[BlockSize:1024, Digest:DIGEST, DigestSize:384, "
                                    + "Oid:2.16.840.1.101.3.4.2.2]"),
                    // 26: SHA384(buf, 64, buf);
                    finding(
                            "DigestContext{ValueAction:SHA-384}",
                            "MessageDigest:SHA-384[BlockSize:1024, Digest:DIGEST, DigestSize:384, "
                                    + "Oid:2.16.840.1.101.3.4.2.2]"),
                    // 28: SHA512_Init(&s5);
                    finding(
                            "DigestContext{ValueAction:SHA-512}",
                            "MessageDigest:SHA-512[BlockSize:1024, Digest:DIGEST, DigestSize:512, "
                                    + "Oid:2.16.840.1.101.3.4.2.3]"),
                    // 29: SHA512(buf, 64, buf);
                    finding(
                            "DigestContext{ValueAction:SHA-512}",
                            "MessageDigest:SHA-512[BlockSize:1024, Digest:DIGEST, DigestSize:512, "
                                    + "Oid:2.16.840.1.101.3.4.2.3]"),
                    // 31: RIPEMD160_Init(&r);
                    finding(
                            "DigestContext{ValueAction:RIPEMD160}",
                            "MessageDigest:RIPEMD-160[Digest:DIGEST, DigestSize:160]"),
                    // 32: RIPEMD160(buf, 64, buf);
                    finding(
                            "DigestContext{ValueAction:RIPEMD160}",
                            "MessageDigest:RIPEMD-160[Digest:DIGEST, DigestSize:160]"),
                    // 34: WHIRLPOOL(buf, 64, buf);
                    finding(
                            "DigestContext{ValueAction:WHIRLPOOL}",
                            "MessageDigest:Whirlpool[BlockSize:512, Digest:DIGEST, DigestSize:512, "
                                    + "NumberOfIterations:10]"),
                    // 35: WHIRLPOOL_Init(NULL);
                    finding(
                            "DigestContext{ValueAction:WHIRLPOOL}",
                            "MessageDigest:Whirlpool[BlockSize:512, Digest:DIGEST, DigestSize:512, "
                                    + "NumberOfIterations:10]"),
                    // 37: MD2(buf, 64, buf);
                    finding(
                            "DigestContext{ValueAction:MD2}",
                            "MessageDigest:MD2[BlockSize:128, Digest:DIGEST, DigestSize:128]"),
                    // 38: MD2_Init(NULL);
                    finding(
                            "DigestContext{ValueAction:MD2}",
                            "MessageDigest:MD2[BlockSize:128, Digest:DIGEST, DigestSize:128]"),
                    // 40: MD4(buf, 64, buf);
                    finding(
                            "DigestContext{ValueAction:MD4}",
                            "MessageDigest:MD4[BlockSize:512, Digest:DIGEST, DigestSize:128]"),
                    // 41: MD4_Init(NULL);
                    finding(
                            "DigestContext{ValueAction:MD4}",
                            "MessageDigest:MD4[BlockSize:512, Digest:DIGEST, DigestSize:128]"),
                    // 43: MDC2(buf, 64, buf);
                    finding(
                            "DigestContext{ValueAction:MDC2}",
                            "MessageDigest:MDC2[BlockSize:64, Digest:DIGEST, DigestSize:128]"),
                    // 44: MDC2_Init(NULL);
                    finding(
                            "DigestContext{ValueAction:MDC2}",
                            "MessageDigest:MDC2[BlockSize:64, Digest:DIGEST, DigestSize:128]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/legacy/OpenSSLLegacyDigestTestFile.cc", this);
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
