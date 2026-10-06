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
 * The signature algorithm fetched by name, the RSA-PSS salt length and the digests named for or
 * passed to a sign/verify operation are reported. The sign and verify calls themselves report
 * nothing: their signature algorithm is the type of the {@code EVP_PKEY}, which is not known at the
 * call.
 */
class OpenSSLEvpSignatureTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 12: EVP_DigestSignInit(ctx, NULL, sign_md, NULL, NULL);
                    finding(
                            "SignatureContext{SignatureAction:SIGN}[DigestContext{ValueAction:SHA-256}]",
                            "Signature:unknown[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], Sign:SIGN]"),
                    // 14: EVP_DigestVerifyInit(ctx, NULL, verify_md, NULL, NULL);
                    finding(
                            "SignatureContext{SignatureAction:VERIFY}[DigestContext{ValueAction:SHA-256}]",
                            "Signature:unknown[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], Verify:VERIFY]"),
                    // 17: EVP_DigestSignInit_ex(ctx, NULL, "SHA2-256", NULL, NULL, NULL, NULL);
                    finding(
                            "SignatureContext{SignatureAction:SIGN}[SignatureContext{Algorithm:SHA-256}]",
                            "Signature:unknown[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], Sign:SIGN]"),
                    // 18: EVP_DigestVerifyInit_ex(ctx, NULL, "SHA256", NULL, NULL, NULL, NULL);
                    finding(
                            "SignatureContext{SignatureAction:VERIFY}[SignatureContext{Algorithm:SHA-256}]",
                            "Signature:unknown[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], Verify:VERIFY]"),
                    // 48: EVP_SIGNATURE_fetch(NULL, "RSA", NULL);
                    finding(
                            "SignatureContext{Algorithm:RSA}",
                            "Signature:RSA-PKCS1-1.5[Oid:1.2.840.113549.1.1.1]"),
                    // 51: const EVP_MD* mgf1_md = EVP_sha256();
                    finding(
                            "DigestContext{ValueAction:SHA-256}",
                            "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]"),
                    // 53: EVP_PKEY_CTX_set_rsa_mgf1_md_name(pctx, "SHA256", NULL);
                    finding(
                            "DigestContext{Algorithm:SHA-256}",
                            "MaskGenerationFunction:MGF1[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.113549.1.1.8]"),
                    // 54: EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32);
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[SignatureContext{SaltSize:256}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[Oid:1.2.840.113549.1.1.10, "
                                    + "SaltLength:256]"),
                    // 55: const EVP_MD* signature_md = EVP_sha256();
                    finding(
                            "DigestContext{ValueAction:SHA-256}",
                            "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]"),
                    // 58: EVP_PKEY_CTX_set_rsa_pss_keygen_md(pctx, pss_keygen_md);
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[DigestContext{ValueAction:SHA-256}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.113549.1.1.10]"),
                    // 59: EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(pctx, "SHA256", NULL);
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[SignatureContext{Algorithm:SHA-256}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.113549.1.1.10]"),
                    // 61: EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(pctx, pss_keygen_mgf1_md);
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[DigestContext{ValueAction:SHA-256}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[MaskGenerationFunction:MGF1[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.113549.1.1.8], Oid:1.2.840.113549.1.1.10]"),
                    // 62: EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(pctx, "SHA256");
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[SignatureContext{Algorithm:SHA-256}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[MaskGenerationFunction:MGF1[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.113549.1.1.8], Oid:1.2.840.113549.1.1.10]"),
                    // 63: EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(pctx, 32);
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[SignatureContext{SaltSize:256}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[Oid:1.2.840.113549.1.1.10, "
                                    + "SaltLength:256]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/signature/OpenSSLEvpSignatureTestFile.cc", this);
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
