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
package com.ibm.plugin.rules.detection.openssl.cipher;

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
 * The parameters set on a cipher context ({@link OpenSSLEvpCipherParameters}): the {@code
 * EVP_CIPHER_CTX_ctrl} command, by name or by value, selects whether its argument is the key
 * length, the RC2 effective key bits, the IV length or the tag length ({@link
 * OpenSSLCipherCtrlFactory}); other commands set no parameter. {@code EVP_CIPHER_CTX_set_padding}
 * enables the standard block padding, PKCS#7, or disables padding ({@link
 * OpenSSLCipherPaddingFactory}).
 */
class OpenSSLEvpCipherParametersTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 4: EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                    finding(
                            "CipherContext{}[CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:BLOWFISH-CBC}], "
                                    + "AlgorithmParameterContext{KeySize:128}]",
                            "BlockCipher:Blowfish-128-CBC[Encrypt:ENCRYPT, KeyLength:128, Mode:CBC]"),
                    // 10: EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                    finding(
                            "CipherContext{}[CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:RC2-CBC}], "
                                    + "AlgorithmParameterContext{KeySize:40}]",
                            "BlockCipher:RC2-40-CBC[Encrypt:ENCRYPT, KeyLength:40, Mode:CBC]"),
                    // 16: EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                    finding(
                            "CipherContext{}[CipherContext{CipherAction:DECRYPT}[CipherContext{ValueAction:AES-128-GCM}], "
                                    + "AlgorithmParameterContext{InitializationVectorSize:128, TagSize:96}]",
                            "AuthenticatedEncryption:AES-128-GCM[BlockSize:128, Decrypt:DECRYPT, "
                                    + "InitializationVectorLength:128, KeyLength:128, Mode:GCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.6, TagLength:96]"),
                    // 23: EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                    finding(
                            "CipherContext{}[CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-128-CCM}], "
                                    + "AlgorithmParameterContext{InitializationVectorSize:56, TagSize:64}]",
                            "AuthenticatedEncryption:AES-128-CCM[BlockSize:128, Encrypt:ENCRYPT, "
                                    + "InitializationVectorLength:56, KeyLength:128, Mode:CCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.7, TagLength:64]"),
                    // 30: EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                    finding(
                            "CipherContext{}[CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-256-GCM}], "
                                    + "AlgorithmParameterContext{InitializationVectorSize:64, TagSize:112}]",
                            "AuthenticatedEncryption:AES-256-GCM[BlockSize:128, Encrypt:ENCRYPT, "
                                    + "InitializationVectorLength:64, KeyLength:256, Mode:GCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.46, TagLength:112]"),
                    // 37: EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                    finding(
                            "CipherContext{}[CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-256-GCM}]]",
                            "AuthenticatedEncryption:AES-256-GCM[BlockSize:128, Encrypt:ENCRYPT, "
                                    + "KeyLength:256, Mode:GCM, Oid:2.16.840.1.101.3.4.1.46]"),
                    // 44: EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                    finding(
                            "CipherContext{}[CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-128-CBC}], "
                                    + "AlgorithmParameterContext{Padding:PKCS7}]",
                            "BlockCipher:AES-128-CBC-PKCS7[BlockSize:128, Encrypt:ENCRYPT, "
                                    + "KeyLength:128, Mode:CBC, Oid:2.16.840.1.101.3.4.1.2, Padding:PKCS7]"),
                    // 50: EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                    finding(
                            "CipherContext{}[CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-128-CBC}]]",
                            "BlockCipher:AES-128-CBC[BlockSize:128, Encrypt:ENCRYPT, KeyLength:128, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.2]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/cipher/OpenSSLEvpCipherParametersTestFile.cc", this);
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
