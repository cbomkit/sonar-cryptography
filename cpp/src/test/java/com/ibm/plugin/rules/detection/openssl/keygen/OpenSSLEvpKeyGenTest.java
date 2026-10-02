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

/** Covers the rules of {@link OpenSSLEvpKeyGen} and its per-algorithm context rules. */
class OpenSSLEvpKeyGenTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 5: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
                    finding(
                            "KeyContext{ValueAction:DSA}[KeyContext{KeySize:2048}, "
                                    + "KeyContext{}[DigestContext{ValueAction:SHA-256}]]",
                            "Signature:DSA-2048-SHA-256[KeyLength:2048, "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1], Oid:2.16.840.1.101.3.4.3.2]"),
                    // 14: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL);
                    finding(
                            "KeyContext{Algorithm:DSA}[DigestContext{Algorithm:SHA-256}]",
                            "Signature:DSA-SHA-256[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], Oid:2.16.840.1.101.3.4.3.2]"),
                    // 19: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
                    finding(
                            "KeyContext{ValueAction:EC}[KeyContext{Curve:EC-prime256v1}]",
                            "PublicKeyEncryption:EC-secp256r1[EllipticCurve:secp256r1, "
                                    + "Oid:1.2.840.10045.2.1]"),
                    // 25: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
                    finding(
                            "KeyContext{ValueAction:EC}[KeyContext{Curve:EC-prime256v1}]",
                            "PublicKeyEncryption:EC-secp256r1[EllipticCurve:secp256r1, "
                                    + "Oid:1.2.840.10045.2.1]"),
                    // 30: EVP_PKEY_CTX *p192 = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
                    finding(
                            "KeyContext{Algorithm:EC}[KeyContext{Curve:EC-P-192}]",
                            "PublicKeyEncryption:EC-secp192r1[EllipticCurve:secp192r1, "
                                    + "Oid:1.2.840.10045.2.1]"),
                    // 32: EVP_PKEY_CTX *p224 = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
                    finding(
                            "KeyContext{Algorithm:EC}[KeyContext{Curve:EC-SECP224R1}]",
                            "PublicKeyEncryption:EC-secp224r1[EllipticCurve:secp224r1, "
                                    + "Oid:1.2.840.10045.2.1]"),
                    // 39: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}[KeyContext{KeySize:2048}, "
                                    + "KeyContext{KeyAction:PRIVATE_KEY_GENERATION}]",
                            "PrivateKey:RSA[KeyLength:2048, "
                                    + "PublicKeyEncryption:RSA-2048[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:2048, Oid:1.2.840.113549.1.1.1]]"),
                    // 46: EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
                    finding(
                            "PrivateKeyContext{Algorithm:RSA}[PrivateKeyContext{KeySize:2048}]",
                            "PrivateKey:RSA[KeyLength:2048, "
                                    + "PublicKeyEncryption:RSA-2048[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:2048, Oid:1.2.840.113549.1.1.1]]"),
                    // 47: EVP_KEYMGMT_fetch(NULL, "ML-KEM-768", NULL);
                    finding(
                            "KeyContext{Algorithm:ML-KEM-768}",
                            "KeyEncapsulationMechanism:ML-KEM-768[Oid:2.16.840.1.101.3.4.4.2, "
                                    + "ParameterSetIdentifier:768]"),
                    // 51: EVP_RSA_gen(3072);
                    finding(
                            "PrivateKeyContext{ValueAction:RSA}[PrivateKeyContext{KeySize:3072}]",
                            "PrivateKey:RSA[KeyLength:3072, "
                                    + "PublicKeyEncryption:RSA-3072[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:3072, Oid:1.2.840.113549.1.1.1]]"),
                    // 52: EVP_EC_gen("P-256");
                    finding(
                            "PrivateKeyContext{ValueAction:EC}[PrivateKeyContext{Curve:EC-P-256}]",
                            "PrivateKey:EC[PublicKeyEncryption:EC-secp256r1[EllipticCurve:secp256r1, "
                                    + "KeyGeneration:KEYGENERATION, Oid:1.2.840.10045.2.1]]"),
                    // 56: EVP_PKEY_CTX *k283 = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
                    finding(
                            "KeyContext{Algorithm:EC}[KeyContext{Curve:EC-sect283k1}]",
                            "PublicKeyEncryption:EC-sect283k1[EllipticCurve:sect283k1, "
                                    + "Oid:1.2.840.10045.2.1]"),
                    // 58: EVP_PKEY_CTX *b163 = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
                    finding(
                            "KeyContext{Algorithm:EC}[KeyContext{Curve:EC-B-163}]",
                            "PublicKeyEncryption:EC-sect163r2[EllipticCurve:sect163r2, "
                                    + "Oid:1.2.840.10045.2.1]"),
                    // 60: EVP_PKEY_CTX *p224 = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
                    finding(
                            "KeyContext{ValueAction:EC}[KeyContext{Curve:EC-secp224r1}]",
                            "PublicKeyEncryption:EC-secp224r1[EllipticCurve:secp224r1, "
                                    + "Oid:1.2.840.10045.2.1]"),
                    // 62: EVP_PKEY_CTX *p224_code = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
                    finding(
                            "KeyContext{ValueAction:EC}[KeyContext{Curve:EC-secp224r1}]",
                            "PublicKeyEncryption:EC-secp224r1[EllipticCurve:secp224r1, "
                                    + "Oid:1.2.840.10045.2.1]"),
                    // 67: EVP_PKEY_Q_keygen(NULL, NULL, "MLKEM1024");
                    finding(
                            "PrivateKeyContext{Algorithm:ML-KEM-1024}",
                            "PrivateKey:ML-KEM[KeyEncapsulationMechanism:ML-KEM-1024["
                                    + "KeyGeneration:KEYGENERATION, Oid:2.16.840.1.101.3.4.4.3, "
                                    + "ParameterSetIdentifier:1024]]"),
                    // 68: EVP_PKEY_Q_keygen(NULL, NULL, "MLDSA65");
                    finding(
                            "PrivateKeyContext{Algorithm:ML-DSA-65}",
                            "PrivateKey:ML-DSA[Signature:ML-DSA-65[KeyGeneration:KEYGENERATION, "
                                    + "Oid:2.16.840.1.101.3.4.3.18, ParameterSetIdentifier:65]]"),
                    // 73: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}[KeyContext{KeySize:3072}, "
                                    + "KeyContext{KeyAction:PRIVATE_KEY_GENERATION}]",
                            "PrivateKey:RSA[KeyLength:3072, "
                                    + "PublicKeyEncryption:RSA-3072[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:3072, Oid:1.2.840.113549.1.1.1]]"),
                    // 81: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL), *unused =
                    // NULL;
                    finding(
                            "KeyContext{ValueAction:RSA}[KeyContext{KeySize:4096}, "
                                    + "KeyContext{KeyAction:PRIVATE_KEY_GENERATION}]",
                            "PrivateKey:RSA[KeyLength:4096, "
                                    + "PublicKeyEncryption:RSA-4096[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:4096, Oid:1.2.840.113549.1.1.1]]"),
                    // 91: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}[KeyContext{KeySize:2048}, "
                                    + "KeyContext{KeyAction:PRIVATE_KEY_GENERATION}]",
                            "PrivateKey:RSA[KeyLength:2048, "
                                    + "PublicKeyEncryption:RSA-2048[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:2048, Oid:1.2.840.113549.1.1.1]]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/keygen/OpenSSLEvpKeyGenTestFile.cc", this);
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
