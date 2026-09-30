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
package com.ibm.plugin.rules.detection.openssl.cms;

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
 * The CMS and PKCS#7 encryption functions report their content encryption cipher with the encrypt
 * operation, a CMS KEK recipient reports its key wrap algorithm, the time-stamping signer digest
 * given by name, the RSA-PSS salt length and the CRMF password-based MAC are reported, and the
 * digest passed to a CMS, PKCS#7 or OCSP signing function is reported once, by the digest rules.
 */
class OpenSSLCmsTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 8: CMS_encrypt(certs, in, EVP_aes_256_cbc(), CMS_BINARY);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-256-CBC}]",
                            "BlockCipher:AES-256-CBC[BlockSize:128, Encrypt:ENCRYPT, KeyLength:256, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.42]"),
                    // 13: CMS_EncryptedData_encrypt_ex(in, cipher, key, 16, 0, NULL, NULL);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{Algorithm:AES-128-GCM}]",
                            "AuthenticatedEncryption:AES-128-GCM[BlockSize:128, Encrypt:ENCRYPT, "
                                    + "KeyLength:128, Mode:GCM, Oid:2.16.840.1.101.3.4.1.6]"),
                    // 17: CMS_add0_recipient_key(cms, NID_id_aes256_wrap, key, 32, id, 8, NULL,
                    // NULL, NULL);
                    finding(
                            "CipherContext{ValueAction:AES-256-WRAP}",
                            "BlockCipher:AES-256-WRAP[BlockSize:128, KeyLength:256, Mode:WRAP, "
                                    + "Oid:2.16.840.1.101.3.4.1.45]"),
                    // 21: PKCS7_encrypt(certs, in, EVP_des_ede3_cbc(), PKCS7_BINARY);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:DESede3-CBC}]",
                            "BlockCipher:DESede168-CBC[BlockSize:64, Encrypt:ENCRYPT, KeyLength:168, "
                                    + "Mode:CBC]"),
                    // 27: CMS_add1_signer(cms, cert, pkey, EVP_sha384(), 0);
                    finding(
                            "DigestContext{ValueAction:SHA-384}",
                            "MessageDigest:SHA-384[BlockSize:1024, Digest:DIGEST, DigestSize:384, "
                                    + "Oid:2.16.840.1.101.3.4.2.2]"),
                    // 28: PKCS7_sign_add_signer(p7, cert, pkey, EVP_sha256(), 0);
                    finding(
                            "DigestContext{ValueAction:SHA-256}",
                            "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]"),
                    // 29: OCSP_basic_sign(resp, cert, pkey, EVP_sha1(), NULL, 0);
                    finding(
                            "DigestContext{ValueAction:SHA-1}",
                            "MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, DigestSize:160, "
                                    + "Oid:1.3.14.3.2.26]"),
                    // 33: EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32);
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[SignatureContext{SaltSize:256}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[Oid:1.2.840.113549.1.1.10, "
                                    + "SaltLength:256]"),
                    // 34: EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}",
                            "ProbabilisticSignatureScheme:RSA-PSS[Oid:1.2.840.113549.1.1.10]"),
                    // 38: TS_CONF_set_signer_digest(conf, "tsa_config", "sha256", ctx);
                    finding(
                            "DigestContext{Algorithm:SHA-256}",
                            "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]"),
                    // 39: TS_RESP_CTX_add_md(ctx, EVP_sha512());
                    finding(
                            "DigestContext{ValueAction:SHA-512}",
                            "MessageDigest:SHA-512[BlockSize:1024, Digest:DIGEST, DigestSize:512, "
                                    + "Oid:2.16.840.1.101.3.4.2.3]"),
                    // 43: OSSL_CRMF_PBMPARAMETER *pbm = OSSL_CRMF_pbmp_new(NULL, 16, NID_sha256,
                    // 500, NID_hmac_sha1);
                    finding(
                            "MacContext{ValueAction:HMAC-SHA1}",
                            "Mac:HMAC-SHA-1[MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:160, Oid:1.3.14.3.2.26], Oid:1.2.840.113549.2.7, Tag:TAG]"),
                    // 43: OSSL_CRMF_PBMPARAMETER *pbm = OSSL_CRMF_pbmp_new(NULL, 16, NID_sha256,
                    // 500, NID_hmac_sha1);
                    finding(
                            "DigestContext{ValueAction:SHA-256}",
                            "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/cms/OpenSSLCmsTestFile.cc", this);
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
