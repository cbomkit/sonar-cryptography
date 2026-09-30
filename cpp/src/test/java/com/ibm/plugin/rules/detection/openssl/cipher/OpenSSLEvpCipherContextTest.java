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
 * A cipher context ({@code EVP_CIPHER_CTX_new}) is reported with the cipher it is initialized with
 * and the parameters set on it, as the JCA {@code Cipher.getInstance} with its {@code init}. The
 * initialization of a context that is created by the caller of the function, in the scanned code or
 * not, is reported on its own with its cipher. An initialization without a cipher of a context
 * initialized elsewhere names no algorithm and is not reported.
 */
class OpenSSLEvpCipherContextTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 4: EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                    finding(
                            "CipherContext{}[CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-256-GCM}], "
                                    + "AlgorithmParameterContext{InitializationVectorSize:96, TagSize:128}]",
                            "AuthenticatedEncryption:AES-256-GCM[BlockSize:128, Encrypt:ENCRYPT, "
                                    + "InitializationVectorLength:96, KeyLength:256, Mode:GCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.46, TagLength:128]"),
                    // 14: EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                    finding(
                            "CipherContext{}[CipherContext{CipherAction:DECRYPT}[CipherContext{ValueAction:RC4}], "
                                    + "AlgorithmParameterContext{KeySize:256}]",
                            "StreamCipher:RC4-256[Decrypt:DECRYPT, KeyLength:256]"),
                    // 22: EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-128-CBC}]",
                            "BlockCipher:AES-128-CBC[BlockSize:128, Encrypt:ENCRYPT, KeyLength:128, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.2]"),
                    // 32: EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, NULL, NULL);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:ChaCha20}]",
                            "StreamCipher:ChaCha20[Encrypt:ENCRYPT]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/cipher/OpenSSLEvpCipherContextTestFile.cc", this);
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
