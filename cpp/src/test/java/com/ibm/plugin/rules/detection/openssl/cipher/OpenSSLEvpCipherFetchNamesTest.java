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
 * Cipher names passed to {@code EVP_CIPHER_fetch} and {@code EVP_get_cipherbyname} are matched
 * case-insensitively and may be OpenSSL aliases.
 */
class OpenSSLEvpCipherFetchNamesTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 4: EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
                    finding(
                            "CipherContext{Algorithm:AES-256-GCM}",
                            "AuthenticatedEncryption:AES-256-GCM[BlockSize:128, KeyLength:256, Mode:GCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.46]"),
                    // 5: EVP_CIPHER_fetch(NULL, "aes-128-cbc", NULL);
                    finding(
                            "CipherContext{Algorithm:aes-128-cbc}",
                            "BlockCipher:AES-128-CBC[BlockSize:128, KeyLength:128, Mode:CBC, "
                                    + "Oid:2.16.840.1.101.3.4.1.2]"),
                    // 6: EVP_CIPHER_fetch(NULL, "id-aes256-GCM", NULL);
                    finding(
                            "CipherContext{Algorithm:AES-256-GCM}",
                            "AuthenticatedEncryption:AES-256-GCM[BlockSize:128, KeyLength:256, Mode:GCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.46]"),
                    // 7: EVP_CIPHER_fetch(NULL, "AES256", NULL);
                    finding(
                            "CipherContext{Algorithm:AES-256-CBC}",
                            "BlockCipher:AES-256-CBC[BlockSize:128, KeyLength:256, Mode:CBC, "
                                    + "Oid:2.16.840.1.101.3.4.1.42]"),
                    // 8: EVP_CIPHER_fetch(NULL, "DES3", NULL);
                    finding(
                            "CipherContext{Algorithm:DESede3-CBC}",
                            "BlockCipher:DESede168-CBC[BlockSize:64, KeyLength:168, Mode:CBC]"),
                    // 9: EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", NULL);
                    finding(
                            "CipherContext{Algorithm:ChaCha20-Poly1305}",
                            "AuthenticatedEncryption:ChaCha20-Poly1305[MessageDigest:Poly1305[Digest:DIGEST]]"),
                    // 13: EVP_get_cipherbyname("des-ede3-cbc");
                    finding(
                            "CipherContext{Algorithm:DESede3-CBC}",
                            "BlockCipher:DESede168-CBC[BlockSize:64, KeyLength:168, Mode:CBC]"),
                    // 14: EVP_get_cipherbyname("BF");
                    finding(
                            "CipherContext{Algorithm:BLOWFISH-CBC}",
                            "BlockCipher:Blowfish-128-CBC[KeyLength:128, Mode:CBC]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/cipher/OpenSSLEvpCipherFetchNamesTestFile.cc", this);
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
