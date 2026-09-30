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
 * The signatures made with a key on certificates, certificate requests and CRLs ({@code X509_sign},
 * ...), their verification, the CMS, PKCS#7 and OCSP signatures, and the encryption of the session
 * key of an envelope ({@code EVP_SealInit} / {@code EVP_OpenInit}) are reported on the key, with
 * the digest given to them ({@link OpenSSLEvpKeyUsage}). The cipher of an envelope is reported with
 * its operation. A key not generated in the scanned code leaves its digest reported on its own.
 */
class OpenSSLKeyUsageSigningTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 8: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
                    finding(
                            "PrivateKeyContext{Algorithm:EC}[SignatureContext{SignatureAction:SIGN}[DigestContext{ValueAction:SHA-256}], "
                                    + "PrivateKeyContext{Curve:EC-P256}]",
                            "PrivateKey:EC[KeyGeneration:KEYGENERATION, "
                                    + "Signature:ECDSA-secp256r1-SHA-256[EllipticCurve:secp256r1, "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1], Oid:1.2.840.10045.4.3.2, Sign:SIGN]]"),
                    // 13: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 3072);
                    finding(
                            "PrivateKeyContext{Algorithm:RSA}[SignatureContext{SignatureAction:SIGN}[DigestContext{ValueAction:SHA-384}], "
                                    + "PrivateKeyContext{KeySize:3072}]",
                            "PrivateKey:RSA[KeyGeneration:KEYGENERATION, "
                                    + "Signature:RSA-PKCS1-1.5-SHA-384[KeyLength:3072, "
                                    + "MessageDigest:SHA-384[BlockSize:1024, Digest:DIGEST, DigestSize:384, "
                                    + "Oid:2.16.840.1.101.3.4.2.2], Oid:1.2.840.113549.1.1.12, Sign:SIGN]]"),
                    // 18: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384");
                    finding(
                            "PrivateKeyContext{Algorithm:EC}[SignatureContext{SignatureAction:SIGN}[DigestContext{ValueAction:SHA-384}], "
                                    + "PrivateKeyContext{Curve:EC-P384}]",
                            "PrivateKey:EC[KeyGeneration:KEYGENERATION, "
                                    + "Signature:ECDSA-secp384r1-SHA-384[EllipticCurve:secp384r1, "
                                    + "MessageDigest:SHA-384[BlockSize:1024, Digest:DIGEST, DigestSize:384, "
                                    + "Oid:2.16.840.1.101.3.4.2.2], Oid:1.2.840.10045.4.3.3, Sign:SIGN]]"),
                    // 23: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 2048);
                    finding(
                            "PrivateKeyContext{Algorithm:RSA}[SignatureContext{SignatureAction:VERIFY}, "
                                    + "PrivateKeyContext{KeySize:2048}]",
                            "PrivateKey:RSA[KeyGeneration:KEYGENERATION, "
                                    + "Signature:RSA-PKCS1-1.5[KeyLength:2048, Oid:1.2.840.113549.1.1.1, "
                                    + "Verify:VERIFY]]"),
                    // 28: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
                    finding(
                            "PrivateKeyContext{Algorithm:EC}[SignatureContext{SignatureAction:SIGN}, "
                                    + "PrivateKeyContext{Curve:EC-P256}]",
                            "PrivateKey:EC[KeyGeneration:KEYGENERATION, "
                                    + "Signature:ECDSA-secp256r1[EllipticCurve:secp256r1, Sign:SIGN]]"),
                    // 33: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
                    finding(
                            "PrivateKeyContext{Algorithm:EC}[SignatureContext{SignatureAction:SIGN}[DigestContext{ValueAction:SHA-512}], "
                                    + "PrivateKeyContext{Curve:EC-P256}]",
                            "PrivateKey:EC[KeyGeneration:KEYGENERATION, "
                                    + "Signature:ECDSA-secp256r1-SHA-512[EllipticCurve:secp256r1, "
                                    + "MessageDigest:SHA-512[BlockSize:1024, Digest:DIGEST, DigestSize:512, "
                                    + "Oid:2.16.840.1.101.3.4.2.3], Oid:1.2.840.10045.4.3.4, Sign:SIGN]]"),
                    // 38: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 2048);
                    finding(
                            "PrivateKeyContext{Algorithm:RSA}[SignatureContext{SignatureAction:SIGN}, "
                                    + "PrivateKeyContext{KeySize:2048}]",
                            "PrivateKey:RSA[KeyGeneration:KEYGENERATION, "
                                    + "Signature:RSA-PKCS1-1.5[KeyLength:2048, Oid:1.2.840.113549.1.1.1, "
                                    + "Sign:SIGN]]"),
                    // 43: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 2048);
                    finding(
                            "PrivateKeyContext{Algorithm:RSA}[SignatureContext{SignatureAction:SIGN}[DigestContext{ValueAction:SHA-256}], "
                                    + "PrivateKeyContext{KeySize:2048}]",
                            "PrivateKey:RSA[KeyGeneration:KEYGENERATION, "
                                    + "Signature:RSA-PKCS1-1.5-SHA-256[KeyLength:2048, "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1], Oid:1.2.840.113549.1.1.11, Sign:SIGN]]"),
                    // 48: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 2048);
                    finding(
                            "PrivateKeyContext{Algorithm:RSA}[CipherContext{CipherAction:ENCRYPT}, "
                                    + "PrivateKeyContext{KeySize:2048}]",
                            "PrivateKey:RSA[PublicKeyEncryption:RSA-2048[Encrypt:ENCRYPT, "
                                    + "KeyGeneration:KEYGENERATION, KeyLength:2048, Oid:1.2.840.113549.1.1.1]]"),
                    // 49: EVP_SealInit(ctx, EVP_aes_256_cbc(), &ek, ekl, iv, &pkey, 1);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-256-CBC}]",
                            "BlockCipher:AES-256-CBC[BlockSize:128, Encrypt:ENCRYPT, KeyLength:256, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.42]"),
                    // 53: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 2048);
                    finding(
                            "PrivateKeyContext{Algorithm:RSA}[CipherContext{CipherAction:DECRYPT}, "
                                    + "PrivateKeyContext{KeySize:2048}]",
                            "PrivateKey:RSA[PublicKeyEncryption:RSA-2048[Decrypt:DECRYPT, "
                                    + "KeyGeneration:KEYGENERATION, KeyLength:2048, Oid:1.2.840.113549.1.1.1]]"),
                    // 54: EVP_OpenInit(ctx, EVP_aes_256_cbc(), ek, ekl, iv, pkey);
                    finding(
                            "CipherContext{CipherAction:DECRYPT}[CipherContext{ValueAction:AES-256-CBC}]",
                            "BlockCipher:AES-256-CBC[BlockSize:128, Decrypt:DECRYPT, KeyLength:256, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.42]"),
                    // 58: X509_sign(cert, pkey, EVP_sha256());
                    finding(
                            "DigestContext{ValueAction:SHA-256}",
                            "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]"),
                    // 62: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
                    finding(
                            "PrivateKeyContext{Algorithm:EC}[SignatureContext{SignatureAction:VERIFY}, "
                                    + "PrivateKeyContext{Curve:EC-P256}]",
                            "PrivateKey:EC[KeyGeneration:KEYGENERATION, "
                                    + "Signature:ECDSA-secp256r1[EllipticCurve:secp256r1, Verify:VERIFY]]"),
                    // 68: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384");
                    finding(
                            "PrivateKeyContext{Algorithm:EC}[SignatureContext{SignatureAction:VERIFY}, "
                                    + "PrivateKeyContext{Curve:EC-P384}]",
                            "PrivateKey:EC[KeyGeneration:KEYGENERATION, "
                                    + "Signature:ECDSA-secp384r1[EllipticCurve:secp384r1, Verify:VERIFY]]"),
                    // 73: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 3072);
                    finding(
                            "PrivateKeyContext{Algorithm:RSA}[SignatureContext{SignatureAction:SIGN}, "
                                    + "PrivateKeyContext{KeySize:3072}]",
                            "PrivateKey:RSA[KeyGeneration:KEYGENERATION, "
                                    + "Signature:RSA-PKCS1-1.5[KeyLength:3072, Oid:1.2.840.113549.1.1.1, "
                                    + "Sign:SIGN]]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/keygen/OpenSSLKeyUsageSigningTestFile.cc", this);
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
