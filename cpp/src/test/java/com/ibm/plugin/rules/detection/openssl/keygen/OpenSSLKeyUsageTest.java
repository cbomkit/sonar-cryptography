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

/**
 * The operations performed with a generated key are reported on that key, as the Python module
 * reports the signature or key exchange made with a private key: a signature, key agreement,
 * encryption or key encapsulation of the key's algorithm, with the digest or padding it uses.
 */
class OpenSSLKeyUsageTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 5: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
                    finding(
                            "PrivateKeyContext{Algorithm:EC}[SignatureContext{SignatureAction:SIGN}[DigestContext{ValueAction:SHA-256}], "
                                    + "PrivateKeyContext{Curve:EC-P-256}]",
                            "PrivateKey:EC[KeyGeneration:KEYGENERATION, "
                                    + "Signature:ECDSA-secp256r1-SHA-256[EllipticCurve:secp256r1, "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.10045.4.3.2, Sign:SIGN]]"),
                    // 13: EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}[KeyContext{KeySize:3072}, "
                                    + "KeyContext{KeyAction:PRIVATE_KEY_GENERATION}[SignatureContext{SignatureAction:VERIFY}[CipherContext{ValueAction:RSA-PSS}, "
                                    + "SignatureContext{ValueAction:RSA-PSS}[SignatureContext{SaltSize:256}], "
                                    + "DigestContext{Algorithm:SHA-256}, "
                                    + "DigestContext{ValueAction:SHA-384}]]]",
                            "PrivateKey:RSA[KeyGeneration:KEYGENERATION, KeyLength:3072, "
                                    + "ProbabilisticSignatureScheme:RSA-PSS[KeyLength:3072, "
                                    + "MaskGenerationFunction:MGF1[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.113549.1.1.8], "
                                    + "MessageDigest:SHA-384[BlockSize:1024, Digest:DIGEST, "
                                    + "DigestSize:384, Oid:2.16.840.1.101.3.4.2.2], "
                                    + "Oid:1.2.840.113549.1.1.10, SaltLength:256, Verify:VERIFY]]"),
                    // 27: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
                    finding(
                            "PrivateKeyContext{Algorithm:X25519}[KeyContext{}[KeyContext{KeyAction:KDF}]]",
                            "PrivateKey:x25519[KeyAgreement:x25519[EllipticCurve:Curve25519, "
                                    + "KeyDerivation:KEYDERIVATION, KeyGeneration:KEYGENERATION, "
                                    + "Oid:1.3.101.110]]"),
                    // 35: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384");
                    finding(
                            "PrivateKeyContext{Algorithm:EC}[KeyContext{}[KeyContext{KeyAction:KDF}], "
                                    + "PrivateKeyContext{Curve:EC-P-384}]",
                            "PrivateKey:EC[KeyAgreement:ECDH[EllipticCurve:secp384r1, "
                                    + "KeyDerivation:KEYDERIVATION, Oid:1.3.132.1.12], "
                                    + "KeyGeneration:KEYGENERATION]"),
                    // 43: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 2048);
                    finding(
                            "PrivateKeyContext{Algorithm:RSA}[KeyContext{}[CipherContext{CipherAction:ENCRYPT}, "
                                    + "CipherContext{ValueAction:RSA-OAEP}], "
                                    + "PrivateKeyContext{KeySize:2048}]",
                            "PrivateKey:RSA[KeyLength:2048, "
                                    + "PublicKeyEncryption:RSA-OAEP[Encrypt:ENCRYPT, "
                                    + "KeyGeneration:KEYGENERATION, KeyLength:2048, "
                                    + "Oid:1.2.840.113549.1.1.7, Padding:OAEP]]"),
                    // 51: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
                    finding(
                            "PrivateKeyContext{Algorithm:ML-KEM-768}[KeyContext{}[KeyContext{KeyAction:ENCAPSULATION}]]",
                            "PrivateKey:ML-KEM[KeyEncapsulationMechanism:ML-KEM-768[Encapsulate:ENCAPSULATE, "
                                    + "KeyGeneration:KEYGENERATION, Oid:2.16.840.1.101.3.4.4.2, "
                                    + "ParameterSetIdentifier:768]]"),
                    // 58: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
                    finding(
                            "PrivateKeyContext{Algorithm:ED25519}[SignatureContext{SignatureAction:SIGN}]",
                            "PrivateKey:Ed25519[Signature:Ed25519[EllipticCurve:Edwards25519, "
                                    + "KeyGeneration:KEYGENERATION, "
                                    + "MessageDigest:SHA-512[BlockSize:1024, Digest:DIGEST, "
                                    + "DigestSize:512, Oid:2.16.840.1.101.3.4.2.3], Oid:1.3.101.112, "
                                    + "Sign:SIGN]]"),
                    // 65: EVP_DigestSignInit(mdctx, NULL, EVP_sha512(), NULL, other);
                    finding(
                            "SignatureContext{SignatureAction:SIGN}[DigestContext{ValueAction:SHA-512}]",
                            "Signature:unknown[MessageDigest:SHA-512[BlockSize:1024, "
                                    + "Digest:DIGEST, DigestSize:512, Oid:2.16.840.1.101.3.4.2.3], "
                                    + "Sign:SIGN]"),
                    // 66: return EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 4096);
                    finding(
                            "PrivateKeyContext{Algorithm:RSA}[PrivateKeyContext{KeySize:4096}]",
                            "PrivateKey:RSA[KeyLength:4096, "
                                    + "PublicKeyEncryption:RSA-4096[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:4096, Oid:1.2.840.113549.1.1.1]]"),
                    // 71: EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
                    finding(
                            "KeyContext{ValueAction:DH}[KeyContext{KeySize:2048}, "
                                    + "KeyContext{KeyAction:PRIVATE_KEY_GENERATION}[KeyContext{}[KeyContext{KeyAction:KDF}]]]",
                            "PrivateKey:FFDH[KeyAgreement:FFDH[KeyDerivation:KEYDERIVATION, "
                                    + "KeyLength:2048, Oid:1.2.840.113549.1.3.1], "
                                    + "KeyGeneration:KEYGENERATION, KeyLength:2048]"),
                    // 81: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 3072);
                    finding(
                            "PrivateKeyContext{Algorithm:RSA}[KeyContext{}[KeyContext{KeyAction:ENCAPSULATION}], "
                                    + "PrivateKeyContext{KeySize:3072}]",
                            "PrivateKey:RSA[KeyEncapsulationMechanism:RSASVE[Encapsulate:ENCAPSULATE, "
                                    + "KeyLength:3072], KeyGeneration:KEYGENERATION, KeyLength:3072]"),
                    // 88: EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
                    finding(
                            "PrivateKeyContext{Algorithm:X25519}[KeyContext{}[KeyContext{KeyAction:ENCAPSULATION}]]",
                            "PrivateKey:x25519[KeyEncapsulationMechanism:DHKEM[Encapsulate:ENCAPSULATE, "
                                    + "KeyAgreement:x25519[EllipticCurve:Curve25519, "
                                    + "Oid:1.3.101.110]], KeyGeneration:KEYGENERATION]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/keygen/OpenSSLKeyUsageTestFile.cc", this);
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
