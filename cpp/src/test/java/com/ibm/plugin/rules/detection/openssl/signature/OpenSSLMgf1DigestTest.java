/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.plugin.rules.detection.openssl.signature;

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
 * The digest of MGF1, the mask generation function of RSA-PSS and RSA-OAEP, is reported as MGF1
 * with that digest, under the scheme: the MGF1 digest an RSA-PSS key is restricted to, given as an
 * {@code EVP_MD} or by name, and the MGF1 digests of the legacy PSS and OAEP encoding functions.
 * Such a digest is not reported on its own as well.
 */
class OpenSSLMgf1DigestTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 5: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA-PSS}[KeyContext{KeySize:2048}, "
                                    + "KeyContext{}[DigestContext{ValueAction:SHA-256}], "
                                    + "KeyContext{}[DigestContext{ValueAction:SHA-512}]]",
                            "ProbabilisticSignatureScheme:RSA-PSS[KeyLength:2048, "
                                    + "MaskGenerationFunction:MGF1[MessageDigest:SHA-512[BlockSize:1024, "
                                    + "Digest:DIGEST, DigestSize:512, Oid:2.16.840.1.101.3.4.2.3], "
                                    + "Oid:1.2.840.113549.1.1.8], "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.113549.1.1.10]"),
                    // 12: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA-PSS}[KeyContext{KeySize:3072}, "
                                    + "DigestContext{Algorithm:SHA-384}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[KeyLength:3072, "
                                    + "MaskGenerationFunction:MGF1[MessageDigest:SHA-384[BlockSize:1024, "
                                    + "Digest:DIGEST, DigestSize:384, Oid:2.16.840.1.101.3.4.2.2], "
                                    + "Oid:1.2.840.113549.1.1.8], Oid:1.2.840.113549.1.1.10]"),
                    // 18: RSA_padding_add_PKCS1_PSS_mgf1(rsa, em, hash, EVP_sha256(), EVP_sha1(),
                    // 20);
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[SignatureContext{SaltSize:160}, "
                                    + "DigestContext{ValueAction:SHA-256}, "
                                    + "DigestContext{ValueAction:SHA-1}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[MaskGenerationFunction:MGF1[MessageDigest:SHA-1[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:160, Oid:1.3.14.3.2.26], "
                                    + "Oid:1.2.840.113549.1.1.8], "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.113549.1.1.10, SaltLength:160]"),
                    // 19: RSA_verify_PKCS1_PSS_mgf1(rsa, hash, EVP_sha384(), EVP_sha224(), em, 20);
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[SignatureContext{SaltSize:160}, "
                                    + "DigestContext{ValueAction:SHA-384}, "
                                    + "DigestContext{ValueAction:SHA-224}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[MaskGenerationFunction:MGF1[MessageDigest:SHA-224[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:224, Oid:2.16.840.1.101.3.4.2.4], "
                                    + "Oid:1.2.840.113549.1.1.8], "
                                    + "MessageDigest:SHA-384[BlockSize:1024, Digest:DIGEST, "
                                    + "DigestSize:384, Oid:2.16.840.1.101.3.4.2.2], "
                                    + "Oid:1.2.840.113549.1.1.10, SaltLength:160]"),
                    // 23: RSA_padding_add_PKCS1_OAEP_mgf1(to, tlen, from, flen, NULL, 0,
                    // EVP_sha256(), EVP_sha1());
                    finding(
                            "CipherContext{ValueAction:RSA-OAEP-MGF1}[DigestContext{ValueAction:SHA-256}, "
                                    + "DigestContext{ValueAction:SHA-1}]",
                            "PublicKeyEncryption:RSA-OAEP[Oid:1.2.840.113549.1.1.7, "
                                    + "Padding:OAEP[MaskGenerationFunction:MGF1[MessageDigest:SHA-1[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:160, Oid:1.3.14.3.2.26], "
                                    + "Oid:1.2.840.113549.1.1.8], "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1]]]"),
                    // 24: RSA_padding_check_PKCS1_OAEP_mgf1(to, tlen, from, flen, 256, NULL, 0,
                    // EVP_sha512(), EVP_sha384());
                    finding(
                            "CipherContext{ValueAction:RSA-OAEP-MGF1}[DigestContext{ValueAction:SHA-512}, "
                                    + "DigestContext{ValueAction:SHA-384}]",
                            "PublicKeyEncryption:RSA-OAEP[Oid:1.2.840.113549.1.1.7, "
                                    + "Padding:OAEP[MaskGenerationFunction:MGF1[MessageDigest:SHA-384[BlockSize:1024, "
                                    + "Digest:DIGEST, DigestSize:384, Oid:2.16.840.1.101.3.4.2.2], "
                                    + "Oid:1.2.840.113549.1.1.8], "
                                    + "MessageDigest:SHA-512[BlockSize:1024, Digest:DIGEST, "
                                    + "DigestSize:512, Oid:2.16.840.1.101.3.4.2.3]]]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/signature/OpenSSLMgf1DigestTestFile.cc", this);
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
