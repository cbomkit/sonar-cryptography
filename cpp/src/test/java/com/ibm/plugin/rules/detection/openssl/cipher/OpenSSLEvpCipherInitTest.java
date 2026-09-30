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
 * The cipher given to {@code EVP_EncryptInit}, {@code EVP_DecryptInit} or {@code EVP_CipherInit} is
 * reported with the operation it is initialized for.
 */
class OpenSSLEvpCipherInitTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 5: EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-256-GCM}]",
                            "AuthenticatedEncryption:AES-256-GCM[BlockSize:128, Encrypt:ENCRYPT, "
                                    + "KeyLength:256, Mode:GCM, Oid:2.16.840.1.101.3.4.1.46]"),
                    // 11: EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL);
                    finding(
                            "CipherContext{CipherAction:DECRYPT}[CipherContext{Algorithm:ChaCha20-Poly1305}]",
                            "AuthenticatedEncryption:ChaCha20-Poly1305[Decrypt:DECRYPT, "
                                    + "MessageDigest:Poly1305[Digest:DIGEST]]"),
                    // 17: EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1);
                    finding(
                            "CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:DESede3-CBC}]",
                            "BlockCipher:DESede168-CBC[BlockSize:64, Encrypt:ENCRYPT, KeyLength:168, "
                                    + "Mode:CBC]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/cipher/OpenSSLEvpCipherInitTestFile.cc", this);
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
