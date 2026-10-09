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
 * The key type is selected when the key generation context is created, and the size or curve set on
 * that context belongs to it; {@code EVP_PKEY_Q_keygen} takes both in one call.
 */
class OpenSSLEvpKeyGenContextTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 6: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}[KeyContext{KeySize:3072}, "
                                    + "KeyContext{KeyAction:PRIVATE_KEY_GENERATION}]",
                            "PrivateKey:RSA[KeyLength:3072, "
                                    + "PublicKeyEncryption:RSA-3072[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:3072, Oid:1.2.840.113549.1.1.1]]"),
                    // 14: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
                    finding(
                            "KeyContext{Algorithm:EC}[KeyContext{Curve:EC-P-384}, "
                                    + "KeyContext{KeyAction:PRIVATE_KEY_GENERATION}]",
                            "PrivateKey:EC[PublicKeyEncryption:EC-secp384r1[EllipticCurve:secp384r1, "
                                    + "KeyGeneration:KEYGENERATION, Oid:1.2.840.10045.2.1]]"),
                    // 22: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
                    finding(
                            "KeyContext{ValueAction:DH}[KeyContext{KeySize:2048}]",
                            "PublicKeyEncryption:FFDH-2048[KeyLength:2048, Oid:1.2.840.113549.1.3.1]"),
                    // 29: EVP_PKEY_CTX *ffdhe = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
                    finding(
                            "KeyContext{ValueAction:DH}[KeyContext{KeySize:3072}]",
                            "PublicKeyEncryption:FFDH-3072[KeyLength:3072, Oid:1.2.840.113549.1.3.1]"),
                    // 31: EVP_PKEY_CTX *rfc5114 = EVP_PKEY_CTX_new_id(EVP_PKEY_DHX, NULL);
                    finding(
                            "KeyContext{ValueAction:DH}[KeyContext{KeySize:1024}]",
                            "PublicKeyEncryption:FFDH-1024[KeyLength:1024, Oid:1.2.840.113549.1.3.1]"),
                    // 33: EVP_PKEY_CTX *rfc5114_dh = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
                    finding(
                            "KeyContext{ValueAction:DH}[KeyContext{KeySize:2048}]",
                            "PublicKeyEncryption:FFDH-2048[KeyLength:2048, Oid:1.2.840.113549.1.3.1]"),
                    // 38: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA-PSS}[KeyContext{KeySize:2048}, "
                                    + "KeyContext{}[DigestContext{ValueAction:SHA-256}], KeyContext{SaltSize:256}]",
                            "ProbabilisticSignatureScheme:RSA-PSS[KeyLength:2048, "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1], Oid:1.2.840.113549.1.1.10, SaltLength:256]"),
                    // 45: EVP_PKEY *rsa = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 4096);
                    finding(
                            "PrivateKeyContext{Algorithm:RSA}[PrivateKeyContext{KeySize:4096}]",
                            "PrivateKey:RSA[KeyLength:4096, "
                                    + "PublicKeyEncryption:RSA-4096[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:4096, Oid:1.2.840.113549.1.1.1]]"),
                    // 46: EVP_PKEY *ec = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
                    finding(
                            "PrivateKeyContext{Algorithm:EC}[PrivateKeyContext{Curve:EC-P-256}]",
                            "PrivateKey:EC[PublicKeyEncryption:EC-secp256r1[EllipticCurve:secp256r1, "
                                    + "KeyGeneration:KEYGENERATION, Oid:1.2.840.10045.2.1]]"),
                    // 47: EVP_PKEY *x25519 = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
                    finding(
                            "PrivateKeyContext{Algorithm:X25519}",
                            "PrivateKey:x25519[KeyAgreement:x25519[EllipticCurve:Curve25519, "
                                    + "KeyGeneration:KEYGENERATION, Oid:1.3.101.110]]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/keygen/OpenSSLEvpKeyGenContextTestFile.cc", this);
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
