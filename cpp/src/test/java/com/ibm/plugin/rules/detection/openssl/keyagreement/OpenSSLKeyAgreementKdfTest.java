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
package com.ibm.plugin.rules.detection.openssl.keyagreement;

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

/** A KDF selected through the EVP_PKEY interface gets the digest that is set on its context. */
class OpenSSLKeyAgreementKdfTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 7: EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, EVP_PKEY_ECDH_KDF_X9_63);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:X963KDF}[KeyDerivationFunctionContext{}[DigestContext{ValueAction:SHA-256}]]",
                            "KeyDerivationFunction:ANSI-KDF-X9.63[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1]]"),
                    // 16: EVP_PKEY_CTX_set_dh_kdf_type(ctx, EVP_PKEY_DH_KDF_X9_42);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:X942KDF-ASN1}[KeyDerivationFunctionContext{}[DigestContext{ValueAction:SHA-384}]]",
                            "KeyDerivationFunction:ANSI-KDF-X9.42-SHA-384-ASN1[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-384[BlockSize:1024, Digest:DIGEST, "
                                    + "DigestSize:384, Oid:2.16.840.1.101.3.4.2.2], "
                                    + "ParameterSetIdentifier:ASN1]"),
                    // 29: EVP_KEM_fetch(NULL, "RSA", NULL);
                    finding(
                            "KeyAgreementContext{Algorithm:RSA}",
                            "KeyEncapsulationMechanism:RSASVE"),
                    // 30: EVP_KEM_fetch(NULL, "ML-KEM-768", NULL);
                    finding(
                            "KeyAgreementContext{Algorithm:ML-KEM-768}",
                            "KeyEncapsulationMechanism:ML-KEM-768[Oid:2.16.840.1.101.3.4.4.2, "
                                    + "ParameterSetIdentifier:768]"),
                    // 31: EVP_KEM_fetch(NULL, "X25519", NULL);
                    finding(
                            "KeyAgreementContext{Algorithm:X25519}",
                            "KeyEncapsulationMechanism:DHKEM[KeyAgreement:x25519[EllipticCurve:Curve25519, "
                                    + "Oid:1.3.101.110]]"),
                    // 32: EVP_KEM_fetch(NULL, "EC", NULL);
                    finding(
                            "KeyAgreementContext{Algorithm:EC}",
                            "KeyEncapsulationMechanism:DHKEM[KeyAgreement:ECDH[Oid:1.3.132.1.12]]"),
                    // 37: OSSL_HPKE_str2suite("x25519,hkdf-sha256,aes-128-gcm", &suite);
                    finding(
                            "KeyAgreementContext{ValueAction:X25519,HKDF-SHA256,AES-128-GCM}",
                            "PublicKeyEncryption:HPKE[AuthenticatedEncryption:AES-128-GCM[BlockSize:128, "
                                    + "KeyLength:128, Mode:GCM, Oid:2.16.840.1.101.3.4.1.6], "
                                    + "KeyDerivationFunction:HKDF-SHA-256[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1]], "
                                    + "KeyEncapsulationMechanism:DHKEM[KeyAgreement:x25519[EllipticCurve:Curve25519, "
                                    + "Oid:1.3.101.110]]]"),
                    // 38: OSSL_HPKE_str2suite("P-384,hkdf-sha384,chacha20-poly1305", &suite);
                    finding(
                            "KeyAgreementContext{ValueAction:P-384,HKDF-SHA384,CHACHA20-POLY1305}",
                            "PublicKeyEncryption:HPKE[AuthenticatedEncryption:ChaCha20-Poly1305[MessageDigest:Poly1305[Digest:DIGEST]], "
                                    + "KeyDerivationFunction:HKDF-SHA-384[MessageDigest:SHA-384[BlockSize:1024, "
                                    + "Digest:DIGEST, DigestSize:384, Oid:2.16.840.1.101.3.4.2.2]], "
                                    + "KeyEncapsulationMechanism:DHKEM[KeyAgreement:ECDH[EllipticCurve:secp384r1, "
                                    + "Oid:1.3.132.1.12]]]"),
                    // 40: OSSL_HPKE_CTX *sender = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE,
                    // default_suite, OSSL_HPKE_ROLE_SENDER, NULL, NULL);
                    finding(
                            "KeyAgreementContext{ValueAction:X25519,HKDF-SHA256,AES-128-GCM}",
                            "PublicKeyEncryption:HPKE[AuthenticatedEncryption:AES-128-GCM[BlockSize:128, "
                                    + "KeyLength:128, Mode:GCM, Oid:2.16.840.1.101.3.4.1.6], "
                                    + "KeyDerivationFunction:HKDF-SHA-256[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1]], "
                                    + "KeyEncapsulationMechanism:DHKEM[KeyAgreement:x25519[EllipticCurve:Curve25519, "
                                    + "Oid:1.3.101.110]]]"),
                    // 42: OSSL_HPKE_CTX *receiver = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE,
                    // explicit_suite, OSSL_HPKE_ROLE_RECEIVER, NULL, NULL);
                    finding(
                            "KeyAgreementContext{ValueAction:P-256,HKDF-SHA256,AES-256-GCM}",
                            "PublicKeyEncryption:HPKE[AuthenticatedEncryption:AES-256-GCM[BlockSize:128, "
                                    + "KeyLength:256, Mode:GCM, Oid:2.16.840.1.101.3.4.1.46], "
                                    + "KeyDerivationFunction:HKDF-SHA-256[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1]], "
                                    + "KeyEncapsulationMechanism:DHKEM[KeyAgreement:ECDH[EllipticCurve:secp256r1, "
                                    + "Oid:1.3.132.1.12]]]"),
                    // 44: OSSL_HPKE_CTX *numeric = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE,
                    // numeric_suite, OSSL_HPKE_ROLE_SENDER, NULL, NULL);
                    finding(
                            "KeyAgreementContext{ValueAction:P-256,HKDF-SHA256,AES-256-GCM}",
                            "PublicKeyEncryption:HPKE[AuthenticatedEncryption:AES-256-GCM[BlockSize:128, "
                                    + "KeyLength:256, Mode:GCM, Oid:2.16.840.1.101.3.4.1.46], "
                                    + "KeyDerivationFunction:HKDF-SHA-256[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1]], "
                                    + "KeyEncapsulationMechanism:DHKEM[KeyAgreement:ECDH[EllipticCurve:secp256r1, "
                                    + "Oid:1.3.132.1.12]]]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/keyagreement/OpenSSLKeyAgreementKdfTestFile.cc", this);
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
