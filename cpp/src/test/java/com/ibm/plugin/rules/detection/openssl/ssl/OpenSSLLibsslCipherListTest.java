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
package com.ibm.plugin.rules.detection.openssl.ssl;

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
 * The cipher suites named in the cipher string of {@code SSL_CTX_set_cipher_list} and {@code
 * SSL_CTX_set_ciphersuites} are reported; keywords and exclusions select no single suite.
 */
class OpenSSLLibsslCipherListTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 4: SSL_CTX_set_cipher_list(ctx,
                    // "ECDHE-RSA-AES256-GCM-SHA384:HIGH:!aNULL:!MD5");
                    finding(
                            "ProtocolContext{CipherSuite:ECDHE-RSA-AES256-GCM-SHA384:HIGH:!aNULL:!MD5}",
                            "TLS:TLS[CipherSuiteCollection:[CipherSuite:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384[AssetCollection:[KeyAgreement:ECDH[Oid:1.3.132.1.12], "
                                    + "AuthenticatedEncryption:AES-256-GCM[BlockSize:128, KeyLength:256, Mode:GCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.46], "
                                    + "PublicKeyEncryption:RSA[MessageDigest:SHA-384[BlockSize:1024, "
                                    + "Digest:DIGEST, DigestSize:384, Oid:2.16.840.1.101.3.4.2.2], "
                                    + "Oid:1.2.840.113549.1.1.1]], IdentifierCollection:[Identifier:0xC0, "
                                    + "Identifier:0x30]]]]"),
                    // 5: SSL_CTX_set_ciphersuites(ctx,
                    // "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
                    finding(
                            "ProtocolContext{CipherSuite:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256}",
                            "TLS:TLS[CipherSuiteCollection:[CipherSuite:TLS_AES_256_GCM_SHA384[AssetCollection:[AuthenticatedEncryption:AES-256-GCM[BlockSize:128, "
                                    + "KeyLength:256, Mode:GCM, Oid:2.16.840.1.101.3.4.1.46], "
                                    + "MessageDigest:SHA-384[BlockSize:1024, Digest:DIGEST, DigestSize:384, "
                                    + "Oid:2.16.840.1.101.3.4.2.2]], IdentifierCollection:[Identifier:0x13, "
                                    + "Identifier:0x02]], "
                                    + "CipherSuite:TLS_CHACHA20_POLY1305_SHA256[AssetCollection:[AuthenticatedEncryption:ChaCha20-Poly1305[MessageDigest:Poly1305[Digest:DIGEST]], "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]], IdentifierCollection:[Identifier:0x13, "
                                    + "Identifier:0x03]]]]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/ssl/OpenSSLLibsslCipherListTestFile.cc", this);
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
