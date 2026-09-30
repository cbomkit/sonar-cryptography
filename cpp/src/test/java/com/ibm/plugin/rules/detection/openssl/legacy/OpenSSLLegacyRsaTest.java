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

/** Covers all rule entries in {@link OpenSSLLegacyRsa}. */
class OpenSSLLegacyRsaTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 17: RSA_generate_key_ex(rsa, 2048, e, NULL);
                    finding(
                            "PrivateKeyContext{ValueAction:RSA}[PrivateKeyContext{KeySize:2048}]",
                            "PrivateKey:RSA[PublicKeyEncryption:RSA-2048[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:2048, Oid:1.2.840.113549.1.1.1]]"),
                    // 18: RSA_generate_multi_prime_key(rsa, 2048, 3, e, NULL);
                    finding(
                            "PrivateKeyContext{ValueAction:RSA}[PrivateKeyContext{KeySize:2048}]",
                            "PrivateKey:RSA[PublicKeyEncryption:RSA-2048[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:2048, Oid:1.2.840.113549.1.1.1]]"),
                    // 20: RSA_public_encrypt(32, buf, buf, rsa, 1);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:RSA-PKCS1-TYPE2}]",
                            "PublicKeyEncryption:RSA[Encrypt:ENCRYPT, Oid:1.2.840.113549.1.1.1, "
                                    + "Padding:PKCS1]"),
                    // 21: RSA_private_decrypt(32, buf, buf, rsa, 1);
                    finding(
                            "CipherContext{CipherAction:DECRYPT}[CipherContext{ValueAction:RSA-PKCS1-TYPE2}]",
                            "PublicKeyEncryption:RSA[Decrypt:DECRYPT, Oid:1.2.840.113549.1.1.1, "
                                    + "Padding:PKCS1]"),
                    // 23: RSA_sign(NID_sha256, buf, 32, buf, &len, rsa);
                    finding(
                            "SignatureContext{SignatureAction:SIGN}[SignatureContext{ValueAction:RSA-SHA256}]",
                            "Signature:RSA-PKCS1-1.5-SHA-256[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.113549.1.1.11, Sign:SIGN]"),
                    // 24: RSA_verify(NID_sha256, buf, 32, buf, 32, rsa);
                    finding(
                            "SignatureContext{SignatureAction:VERIFY}[SignatureContext{ValueAction:RSA-SHA256}]",
                            "Signature:RSA-PKCS1-1.5-SHA-256[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.113549.1.1.11, Verify:VERIFY]"),
                    // 29: RSA_sign(md5_nid, buf, 32, buf, &len, rsa);
                    finding(
                            "SignatureContext{SignatureAction:SIGN}[SignatureContext{ValueAction:RSA-MD5}]",
                            "Signature:RSA-PKCS1-1.5-MD5[MessageDigest:MD5[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:128], Oid:1.2.840.113549.1.1.4, Sign:SIGN]"),
                    // 30: RSA_verify(md5_nid, buf, 32, buf, 32, rsa);
                    finding(
                            "SignatureContext{SignatureAction:VERIFY}[SignatureContext{ValueAction:RSA-MD5}]",
                            "Signature:RSA-PKCS1-1.5-MD5[MessageDigest:MD5[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:128], Oid:1.2.840.113549.1.1.4, Verify:VERIFY]"),
                    // 32: RSA_private_encrypt(32, buf, buf, rsa, 1);
                    finding(
                            "SignatureContext{SignatureAction:SIGN}[SignatureContext{ValueAction:RSA-PKCS1}]",
                            "Signature:RSA-PKCS1-1.5[Oid:1.2.840.113549.1.1.1, Padding:PKCS1, Sign:SIGN]"),
                    // 33: RSA_public_decrypt(32, buf, buf, rsa, 1);
                    finding(
                            "SignatureContext{SignatureAction:VERIFY}[SignatureContext{ValueAction:RSA-PKCS1}]",
                            "Signature:RSA-PKCS1-1.5[Oid:1.2.840.113549.1.1.1, Padding:PKCS1, "
                                    + "Verify:VERIFY]"),
                    // 35: RSA_padding_add_PKCS1_PSS(rsa, em, mhash, EVP_sha256(), 32);
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[SignatureContext{SaltSize:256}, "
                                    + "DigestContext{ValueAction:SHA-256}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.113549.1.1.10, SaltLength:256]"),
                    // 36: RSA_padding_add_PKCS1_PSS_mgf1(rsa, em, mhash, NULL, NULL, 32);
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[SignatureContext{SaltSize:256}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[Oid:1.2.840.113549.1.1.10, "
                                    + "SaltLength:256]"),
                    // 37: RSA_verify_PKCS1_PSS(rsa, mhash, EVP_sha256(), em, 32);
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[SignatureContext{SaltSize:256}, "
                                    + "DigestContext{ValueAction:SHA-256}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.113549.1.1.10, SaltLength:256]"),
                    // 38: RSA_verify_PKCS1_PSS_mgf1(rsa, mhash, NULL, NULL, em, 32);
                    finding(
                            "SignatureContext{ValueAction:RSA-PSS}[SignatureContext{SaltSize:256}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[Oid:1.2.840.113549.1.1.10, "
                                    + "SaltLength:256]"),
                    // 40: RSA_padding_add_PKCS1_OAEP(buf, 256, buf, 32, buf, 16);
                    finding(
                            "CipherContext{ValueAction:RSA-OAEP}",
                            "PublicKeyEncryption:RSA-OAEP[Oid:1.2.840.113549.1.1.7, Padding:OAEP]"),
                    // 41: RSA_padding_add_PKCS1_OAEP_mgf1(buf, 256, buf, 32, buf, 16, EVP_sha384(),
                    // NULL);
                    finding(
                            "CipherContext{ValueAction:RSA-OAEP-MGF1}[DigestContext{ValueAction:SHA-384}]",
                            "PublicKeyEncryption:RSA-OAEP[MessageDigest:SHA-384[BlockSize:1024, "
                                    + "Digest:DIGEST, DigestSize:384, Oid:2.16.840.1.101.3.4.2.2], "
                                    + "Oid:1.2.840.113549.1.1.7, Padding:OAEP]"),
                    // 43: RSA_padding_add_PKCS1_type_1(buf, 256, buf, 32);
                    finding(
                            "CipherContext{ValueAction:RSA-PKCS1}",
                            "Signature:RSA-PKCS1-1.5[Oid:1.2.840.113549.1.1.1, Padding:PKCS1]"),
                    // 44: RSA_padding_add_PKCS1_type_2(buf, 256, buf, 32);
                    finding(
                            "CipherContext{ValueAction:RSA-PKCS1-TYPE2}",
                            "PublicKeyEncryption:RSA[Oid:1.2.840.113549.1.1.1, Padding:PKCS1]"),
                    // 45: RSA_padding_check_PKCS1_type_1(buf, 256, buf, 32, 256);
                    finding(
                            "CipherContext{ValueAction:RSA-PKCS1}",
                            "Signature:RSA-PKCS1-1.5[Oid:1.2.840.113549.1.1.1, Padding:PKCS1]"),
                    // 46: RSA_padding_check_PKCS1_type_2(buf, 256, buf, 32, 256);
                    finding(
                            "CipherContext{ValueAction:RSA-PKCS1-TYPE2}",
                            "PublicKeyEncryption:RSA[Oid:1.2.840.113549.1.1.1, Padding:PKCS1]"),
                    // 47: RSA_padding_check_PKCS1_OAEP(buf, 256, buf, 32, 256, buf, 16);
                    finding(
                            "CipherContext{ValueAction:RSA-OAEP}",
                            "PublicKeyEncryption:RSA-OAEP[Oid:1.2.840.113549.1.1.7, Padding:OAEP]"),
                    // 48: RSA_padding_check_PKCS1_OAEP_mgf1(buf, 256, buf, 32, 256, buf, 16, NULL,
                    // NULL);
                    finding(
                            "CipherContext{ValueAction:RSA-OAEP-MGF1}",
                            "PublicKeyEncryption:RSA-OAEP[Oid:1.2.840.113549.1.1.7, Padding:OAEP]"),
                    // 49: RSA_padding_add_X931(buf, 256, buf, 32);
                    finding("CipherContext{ValueAction:RSA-X931}", "Signature:ANSI X9.31"),
                    // 50: RSA_padding_check_X931(buf, 256, buf, 32, 256);
                    finding("CipherContext{ValueAction:RSA-X931}", "Signature:ANSI X9.31"),
                    // 51: RSA_padding_add_none(buf, 256, buf, 32);
                    finding(
                            "CipherContext{ValueAction:RSA-NO-PADDING}",
                            "PublicKeyEncryption:RSA[Oid:1.2.840.113549.1.1.1]"),
                    // 52: RSA_padding_check_none(buf, 256, buf, 32, 256);
                    finding(
                            "CipherContext{ValueAction:RSA-NO-PADDING}",
                            "PublicKeyEncryption:RSA[Oid:1.2.840.113549.1.1.1]"),
                    // 53: RSA_generate_key(2048, 65537, NULL, NULL);
                    finding(
                            "PrivateKeyContext{ValueAction:RSA}[PrivateKeyContext{KeySize:2048}]",
                            "PrivateKey:RSA[PublicKeyEncryption:RSA-2048[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:2048, Oid:1.2.840.113549.1.1.1]]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/legacy/OpenSSLLegacyRsaTestFile.cc", this);
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
