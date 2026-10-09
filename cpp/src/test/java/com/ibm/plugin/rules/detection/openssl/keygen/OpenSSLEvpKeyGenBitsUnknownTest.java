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
 * A size argument has a value only when it is a positive integer: an undeclared macro, a number
 * literal that is out of range or invalid, an enum constant whose value is not known, a constant
 * expression that overflows or shifts out of range, and a size that is not positive give no size.
 */
class OpenSSLEvpKeyGenBitsUnknownTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 6: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}",
                            "PublicKeyEncryption:RSA[Oid:1.2.840.113549.1.1.1]"),
                    // 11: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}",
                            "PublicKeyEncryption:RSA[Oid:1.2.840.113549.1.1.1]"),
                    // 16: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}",
                            "PublicKeyEncryption:RSA[Oid:1.2.840.113549.1.1.1]"),
                    // 21: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}",
                            "PublicKeyEncryption:RSA[Oid:1.2.840.113549.1.1.1]"),
                    // 28: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}",
                            "PublicKeyEncryption:RSA[Oid:1.2.840.113549.1.1.1]"),
                    // 33: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}",
                            "PublicKeyEncryption:RSA[Oid:1.2.840.113549.1.1.1]"),
                    // 38: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}",
                            "PublicKeyEncryption:RSA[Oid:1.2.840.113549.1.1.1]"),
                    // 42: PKCS5_PBKDF2_HMAC(pass, 8, salt, 16, 10000, EVP_sha256(), APP_KEY_BYTES,
                    // out);
                    finding(
                            "KeyDerivationFunctionContext{ValueAction:PBKDF2-HMAC}[KeyDerivationFunctionContext{SaltSize:128}, "
                                    + "KeyDerivationFunctionContext{IterationCount:10000}, "
                                    + "DigestContext{ValueAction:SHA-256}]",
                            "PasswordBasedKeyDerivationFunction:PBKDF2-SHA-256[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], NumberOfIterations:10000, "
                                    + "SaltLength:128]"),
                    // 46: EVP_RSA_gen(APP_RSA_BITS);
                    finding(
                            "PrivateKeyContext{ValueAction:RSA}",
                            "PrivateKey:RSA[PublicKeyEncryption:RSA[KeyGeneration:KEYGENERATION, "
                                    + "Oid:1.2.840.113549.1.1.1]]"),
                    // 50: EVP_PKEY_Q_keygen(NULL, NULL, "RSA", -1);
                    finding(
                            "PrivateKeyContext{Algorithm:RSA}",
                            "PrivateKey:RSA[PublicKeyEncryption:RSA[KeyGeneration:KEYGENERATION, "
                                    + "Oid:1.2.840.113549.1.1.1]]"),
                    // 54: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}",
                            "PublicKeyEncryption:RSA[Oid:1.2.840.113549.1.1.1]"),
                    // 59: EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
                    finding(
                            "KeyContext{ValueAction:RSA}",
                            "PublicKeyEncryption:RSA[Oid:1.2.840.113549.1.1.1]"),
                    // 66: AES_ecb_encrypt(in, out, &key, AES_ENCRYPT);
                    finding(
                            "CipherContext{ValueAction:AES-ECB}[CipherContext{ValueAction:AES}]",
                            "BlockCipher:AES-ECB[BlockSize:128, Mode:ECB, Oid:2.16.840.1.101.3.4.1]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/keygen/OpenSSLEvpKeyGenBitsUnknownTestFile.cc", this);
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
