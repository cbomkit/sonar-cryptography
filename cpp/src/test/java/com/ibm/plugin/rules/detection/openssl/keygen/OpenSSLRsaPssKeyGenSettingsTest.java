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
package com.ibm.plugin.rules.detection.openssl.keygen;

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
 * The RSA-PSS key generation settings, which are only accepted on an RSA-PSS key generation
 * context, report RSA-PSS with the digest, MGF1 digest or salt length they restrict the key to when
 * the context is created elsewhere, as {@code EVP_PKEY_CTX_set_rsa_pss_saltlen} does for a signing
 * context. On a context created in the analyzed code they are reported with the key, and not again
 * on their own.
 */
class OpenSSLRsaPssKeyGenSettingsTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 5: EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, EVP_sha256());
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[DigestContext{ValueAction:SHA-256}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.113549.1.1.10]"),
                    // 6: EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx, EVP_sha384());
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[DigestContext{ValueAction:SHA-384}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[MaskGenerationFunction:MGF1[MessageDigest:SHA-384[BlockSize:1024, "
                                    + "Digest:DIGEST, DigestSize:384, Oid:2.16.840.1.101.3.4.2.2], "
                                    + "Oid:1.2.840.113549.1.1.8], Oid:1.2.840.113549.1.1.10]"),
                    // 7: EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx, "SHA512", NULL);
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[SignatureContext{Algorithm:SHA-512}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[MessageDigest:SHA-512[BlockSize:1024, "
                                    + "Digest:DIGEST, DigestSize:512, Oid:2.16.840.1.101.3.4.2.3], "
                                    + "Oid:1.2.840.113549.1.1.10]"),
                    // 8: EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx, "SHA224");
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[SignatureContext{Algorithm:SHA-224}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[MaskGenerationFunction:MGF1[MessageDigest:SHA-224[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:224, Oid:2.16.840.1.101.3.4.2.4], "
                                    + "Oid:1.2.840.113549.1.1.8], Oid:1.2.840.113549.1.1.10]"),
                    // 9: EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, 32);
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[SignatureContext{SaltSize:256}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[Oid:1.2.840.113549.1.1.10, "
                                    + "SaltLength:256]"),
                    // 13: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA-PSS}[KeyContext{KeySize:3072}, "
                                    + "KeyContext{}[DigestContext{ValueAction:SHA-512}], "
                                    + "KeyContext{SaltSize:512}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[KeyLength:3072, "
                                    + "MessageDigest:SHA-512[BlockSize:1024, Digest:DIGEST, "
                                    + "DigestSize:512, Oid:2.16.840.1.101.3.4.2.3], "
                                    + "Oid:1.2.840.113549.1.1.10, SaltLength:512]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/keygen/OpenSSLRsaPssKeyGenSettingsTestFile.cc", this);
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
