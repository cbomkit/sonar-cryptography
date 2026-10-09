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
 * A context initialized again with another algorithm is another use of it: each cipher or digest it
 * is initialized with is reported with the calls made on the context until the next one.
 */
class OpenSSLEvpCipherContextReuseTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 4: EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                    finding(
                            "CipherContext{}[CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:AES-128-CBC}], "
                                    + "CipherContext{CipherAction:DECRYPT}[CipherContext{ValueAction:DESede3-CBC}]]",
                            "BlockCipher:AES-128-CBC[BlockSize:128, Encrypt:ENCRYPT, KeyLength:128, "
                                    + "Mode:CBC, Oid:2.16.840.1.101.3.4.1.2]",
                            "BlockCipher:DESede168-CBC[BlockSize:64, Decrypt:DECRYPT, KeyLength:168, "
                                    + "Mode:CBC]"),
                    // 11: EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                    finding(
                            "CipherContext{}[CipherContext{CipherAction:ENCRYPT}[CipherContext{ValueAction:RC4}], "
                                    + "AlgorithmParameterContext{KeySize:128}]",
                            "StreamCipher:RC4-128[Encrypt:ENCRYPT, KeyLength:128]"),
                    // 19: EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
                    finding(
                            "DigestContext{ValueAction:SHA-1}",
                            "MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, DigestSize:160, "
                                    + "Oid:1.3.14.3.2.26]"),
                    // 21: EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
                    finding(
                            "DigestContext{ValueAction:SHA-512}",
                            "MessageDigest:SHA-512[BlockSize:1024, Digest:DIGEST, DigestSize:512, "
                                    + "Oid:2.16.840.1.101.3.4.2.3]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/cipher/OpenSSLEvpCipherContextReuseTestFile.cc", this);
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
