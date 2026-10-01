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

/**
 * The legacy key generation functions report a private key holding the algorithm, with the key size
 * they are given, or with the group, parameters or curve of the object the key is generated for.
 * Domain parameters and EC key objects on their own are reported as the algorithm.
 */
class OpenSSLLegacyKeyTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 8: RSA_generate_key_ex(rsa, 3072, e, NULL);
                    finding(
                            "PrivateKeyContext{ValueAction:RSA}[PrivateKeyContext{KeySize:3072}]",
                            "PrivateKey:RSA[KeyLength:3072, "
                                    + "PublicKeyEncryption:RSA-3072[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:3072, Oid:1.2.840.113549.1.1.1]]"),
                    // 9: RSA *old = RSA_generate_key(1024, 65537, NULL, NULL);
                    finding(
                            "PrivateKeyContext{ValueAction:RSA}[PrivateKeyContext{KeySize:1024}]",
                            "PrivateKey:RSA[KeyLength:1024, "
                                    + "PublicKeyEncryption:RSA-1024[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:1024, Oid:1.2.840.113549.1.1.1]]"),
                    // 11: RSA_generate_multi_prime_key(multi, 4096, 3, e, NULL);
                    finding(
                            "PrivateKeyContext{ValueAction:RSA}[PrivateKeyContext{KeySize:4096}]",
                            "PrivateKey:RSA[KeyLength:4096, "
                                    + "PublicKeyEncryption:RSA-4096[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:4096, Oid:1.2.840.113549.1.1.1]]"),
                    // 16: DH_generate_key(dh);
                    finding(
                            "PrivateKeyContext{ValueAction:DH}[KeyContext{ValueAction:DH-2048-256}]",
                            "PrivateKey:FFDH[KeyLength:2048, "
                                    + "PublicKeyEncryption:FFDH-2048[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:2048, Oid:1.2.840.113549.1.3.1]]"),
                    // 20: DH *unrelated = DH_get_1024_160();
                    finding(
                            "KeyContext{ValueAction:DH-1024-160}",
                            "PublicKeyEncryption:FFDH-1024[KeyLength:1024, Oid:1.2.840.113549.1.3.1]"),
                    // 23: DH_get_2048_224();
                    finding(
                            "KeyContext{ValueAction:DH-2048-224}",
                            "PublicKeyEncryption:FFDH-2048[KeyLength:2048, Oid:1.2.840.113549.1.3.1]"),
                    // 24: DH_generate_key(dh);
                    finding(
                            "PrivateKeyContext{ValueAction:DH}[KeyContext{ValueAction:DH}[KeyContext{KeySize:3072}]]",
                            "PrivateKey:FFDH[KeyLength:3072, "
                                    + "PublicKeyEncryption:FFDH-3072[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:3072, Oid:1.2.840.113549.1.3.1]]"),
                    // 30: DH_generate_key(dh);
                    finding(
                            "PrivateKeyContext{ValueAction:DH}[KeyContext{ValueAction:DH}[KeyContext{KeySize:2048}]]",
                            "PrivateKey:FFDH[KeyLength:2048, "
                                    + "PublicKeyEncryption:FFDH-2048[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:2048, Oid:1.2.840.113549.1.3.1]]"),
                    // 36: DSA_generate_key(dsa);
                    finding(
                            "PrivateKeyContext{ValueAction:DSA}[KeyContext{ValueAction:DSA}[KeyContext{KeySize:2048}]]",
                            "PrivateKey:DSA[KeyLength:2048, "
                                    + "Signature:DSA-2048[KeyGeneration:KEYGENERATION, KeyLength:2048, "
                                    + "Oid:1.2.840.10040.4.1]]"),
                    // 41: EC_KEY_generate_key(key);
                    finding(
                            "PrivateKeyContext{ValueAction:EC}[KeyContext{ValueAction:EC-P256}]",
                            "PrivateKey:EC[PublicKeyEncryption:EC-secp256r1[EllipticCurve:secp256r1, "
                                    + "KeyGeneration:KEYGENERATION, Oid:1.2.840.10045.2.1]]"),
                    // 48: EC_KEY_generate_key(key);
                    finding(
                            "PrivateKeyContext{ValueAction:EC}[KeyContext{}[KeyContext{ValueAction:EC-P384}]]",
                            "PrivateKey:EC[PublicKeyEncryption:EC-secp384r1[EllipticCurve:secp384r1, "
                                    + "KeyGeneration:KEYGENERATION, Oid:1.2.840.10045.2.1]]"),
                    // 52: EC_GROUP *group = EC_GROUP_new_curve_GFp(p, a, b, NULL);
                    finding(
                            "KeyContext{ValueAction:EC}",
                            "PublicKeyEncryption:EC[Oid:1.2.840.10045.2.1]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/legacy/OpenSSLLegacyKeyTestFile.cc", this);
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
