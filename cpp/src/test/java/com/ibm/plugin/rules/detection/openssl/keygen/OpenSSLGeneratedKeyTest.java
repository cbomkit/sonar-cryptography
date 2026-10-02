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
 * A generated asymmetric key is reported as a private key holding its algorithm, as the Java and
 * Python modules report generated keys. Generated domain parameters are reported as the algorithm.
 */
class OpenSSLGeneratedKeyTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 6: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}[KeyContext{KeySize:3072}, "
                                    + "KeyContext{KeyAction:PRIVATE_KEY_GENERATION}]",
                            "PrivateKey:RSA[KeyLength:3072, "
                                    + "PublicKeyEncryption:RSA-3072[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:3072, Oid:1.2.840.113549.1.1.1]]"),
                    // 14: return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
                    finding(
                            "PrivateKeyContext{Algorithm:EC}[PrivateKeyContext{Curve:EC-P-256}]",
                            "PrivateKey:EC[PublicKeyEncryption:EC-secp256r1[EllipticCurve:secp256r1, "
                                    + "KeyGeneration:KEYGENERATION, Oid:1.2.840.10045.2.1]]"),
                    // 19: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
                    finding(
                            "KeyContext{ValueAction:DH}[KeyContext{KeySize:2048}]",
                            "PublicKeyEncryption:FFDH-2048[KeyLength:2048, Oid:1.2.840.113549.1.3.1]"),
                    // 28: RSA_generate_key_ex(rsa, 2048, e, NULL);
                    finding(
                            "PrivateKeyContext{ValueAction:RSA}[PrivateKeyContext{KeySize:2048}]",
                            "PrivateKey:RSA[KeyLength:2048, "
                                    + "PublicKeyEncryption:RSA-2048[KeyGeneration:KEYGENERATION, "
                                    + "KeyLength:2048, Oid:1.2.840.113549.1.1.1]]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/keygen/OpenSSLGeneratedKeyTestFile.cc", this);
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
