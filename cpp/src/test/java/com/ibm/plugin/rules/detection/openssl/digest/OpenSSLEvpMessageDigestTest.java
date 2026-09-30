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
package com.ibm.plugin.rules.detection.openssl.digest;

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

/** Covers all rule entries in {@link OpenSSLEvpMessageDigest}. */
class OpenSSLEvpMessageDigestTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 4: EVP_md2();
                    finding(
                            "DigestContext{ValueAction:MD2}",
                            "MessageDigest:MD2[BlockSize:128, Digest:DIGEST, DigestSize:128]"),
                    // 5: EVP_md4();
                    finding(
                            "DigestContext{ValueAction:MD4}",
                            "MessageDigest:MD4[BlockSize:512, Digest:DIGEST, DigestSize:128]"),
                    // 6: EVP_md5();
                    finding(
                            "DigestContext{ValueAction:MD5}",
                            "MessageDigest:MD5[BlockSize:512, Digest:DIGEST, DigestSize:128]"),
                    // 7: EVP_mdc2();
                    finding(
                            "DigestContext{ValueAction:MDC2}",
                            "MessageDigest:MDC2[BlockSize:64, Digest:DIGEST, DigestSize:128]"),
                    // 8: EVP_sha1();
                    finding(
                            "DigestContext{ValueAction:SHA-1}",
                            "MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, DigestSize:160, "
                                    + "Oid:1.3.14.3.2.26]"),
                    // 9: EVP_sha224();
                    finding(
                            "DigestContext{ValueAction:SHA-224}",
                            "MessageDigest:SHA-224[BlockSize:512, Digest:DIGEST, DigestSize:224, "
                                    + "Oid:2.16.840.1.101.3.4.2.4]"),
                    // 10: EVP_sha256();
                    finding(
                            "DigestContext{ValueAction:SHA-256}",
                            "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]"),
                    // 11: EVP_sha384();
                    finding(
                            "DigestContext{ValueAction:SHA-384}",
                            "MessageDigest:SHA-384[BlockSize:1024, Digest:DIGEST, DigestSize:384, "
                                    + "Oid:2.16.840.1.101.3.4.2.2]"),
                    // 12: EVP_sha512();
                    finding(
                            "DigestContext{ValueAction:SHA-512}",
                            "MessageDigest:SHA-512[BlockSize:1024, Digest:DIGEST, DigestSize:512, "
                                    + "Oid:2.16.840.1.101.3.4.2.3]"),
                    // 13: EVP_sha512_224();
                    finding(
                            "DigestContext{ValueAction:SHA-512/224}",
                            "MessageDigest:SHA-512/224[BlockSize:1024, Digest:DIGEST, DigestSize:224, "
                                    + "MessageDigest:SHA-512[BlockSize:1024, Digest:DIGEST, DigestSize:512, "
                                    + "Oid:2.16.840.1.101.3.4.2.3], Oid:2.16.840.1.101.3.4.2.5]"),
                    // 14: EVP_sha512_256();
                    finding(
                            "DigestContext{ValueAction:SHA-512/256}",
                            "MessageDigest:SHA-512/256[BlockSize:1024, Digest:DIGEST, DigestSize:256, "
                                    + "MessageDigest:SHA-512[BlockSize:1024, Digest:DIGEST, DigestSize:512, "
                                    + "Oid:2.16.840.1.101.3.4.2.3], Oid:2.16.840.1.101.3.4.2.6]"),
                    // 15: EVP_sha3_224();
                    finding(
                            "DigestContext{ValueAction:SHA3-224}",
                            "MessageDigest:SHA3-224[BlockSize:1152, Digest:DIGEST, DigestSize:224, "
                                    + "Oid:2.16.840.1.101.3.4.2.7]"),
                    // 16: EVP_sha3_256();
                    finding(
                            "DigestContext{ValueAction:SHA3-256}",
                            "MessageDigest:SHA3-256[BlockSize:1088, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.8]"),
                    // 17: EVP_sha3_384();
                    finding(
                            "DigestContext{ValueAction:SHA3-384}",
                            "MessageDigest:SHA3-384[BlockSize:832, Digest:DIGEST, DigestSize:384, "
                                    + "Oid:2.16.840.1.101.3.4.2.9]"),
                    // 18: EVP_sha3_512();
                    finding(
                            "DigestContext{ValueAction:SHA3-512}",
                            "MessageDigest:SHA3-512[BlockSize:576, Digest:DIGEST, DigestSize:512, "
                                    + "Oid:2.16.840.1.101.3.4.2.10]"),
                    // 19: EVP_shake128();
                    finding(
                            "DigestContext{ValueAction:SHAKE128}",
                            "ExtendableOutputFunction:SHAKE128[Digest:DIGEST, ParameterSetIdentifier:128]"),
                    // 20: EVP_shake256();
                    finding(
                            "DigestContext{ValueAction:SHAKE256}",
                            "ExtendableOutputFunction:SHAKE256[Digest:DIGEST, ParameterSetIdentifier:256]"),
                    // 21: EVP_ripemd160();
                    finding(
                            "DigestContext{ValueAction:RIPEMD160}",
                            "MessageDigest:RIPEMD-160[Digest:DIGEST, DigestSize:160]"),
                    // 22: EVP_whirlpool();
                    finding(
                            "DigestContext{ValueAction:WHIRLPOOL}",
                            "MessageDigest:Whirlpool[BlockSize:512, Digest:DIGEST, DigestSize:512, "
                                    + "NumberOfIterations:10]"),
                    // 23: EVP_blake2b512();
                    finding(
                            "DigestContext{ValueAction:BLAKE2B-512}",
                            "MessageDigest:BLAKE2b-512[Digest:DIGEST, DigestSize:512, SaltLength:128]"),
                    // 24: EVP_blake2s256();
                    finding(
                            "DigestContext{ValueAction:BLAKE2S-256}",
                            "MessageDigest:BLAKE2s-256[Digest:DIGEST, DigestSize:256, SaltLength:64]"),
                    // 25: EVP_sm3();
                    finding(
                            "DigestContext{ValueAction:SM3}",
                            "MessageDigest:SM3[Digest:DIGEST, DigestSize:256]"),
                    // 26: EVP_md5_sha1();
                    finding(
                            "DigestContext{ValueAction:MD5-SHA1}",
                            "MessageDigest:MD5-SHA1[Digest:DIGEST, DigestSize:288]"),
                    // 28: EVP_MD_fetch(NULL, "SHA256", NULL);
                    finding(
                            "DigestContext{Algorithm:SHA-256}",
                            "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]"),
                    // 29: EVP_get_digestbyname("SHA256");
                    finding(
                            "DigestContext{Algorithm:SHA-256}",
                            "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]"),
                    // 33: EVP_Q_digest(NULL, "SHA256", NULL, NULL, 0, NULL, NULL);
                    finding(
                            "DigestContext{Algorithm:SHA-256}",
                            "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]"),
                    // 37: EVP_MD_fetch(NULL, digest_name, NULL);
                    finding(
                            "DigestContext{Algorithm:SHA-256}",
                            "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]"),
                    // 40: EVP_MD_fetch(NULL, "SHA2-256", NULL);
                    finding(
                            "DigestContext{Algorithm:SHA-256}",
                            "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/digest/OpenSSLEvpMessageDigestTestFile.cc", this);
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
