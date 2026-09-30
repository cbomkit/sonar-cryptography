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
 * A TLS context created with {@code SSL_CTX_new} or {@code SSL_CTX_new_ex} is reported as one
 * protocol ({@link OpenSSLSslContext}): the protocol of its method, with the version, cipher
 * suites, groups, signature algorithms and ephemeral DH group configured on it and on the
 * connections created from it with {@code SSL_new}. A version range gives one protocol per version.
 */
class OpenSSLSslContextTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 4: SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
                    finding(
                            "ProtocolContext{}[ProtocolContext{CipherSuite:ECDHE-RSA-AES256-GCM-SHA384}, "
                                    + "ProtocolContext{CipherSuite:TLS_AES_256_GCM_SHA384}, "
                                    + "ProtocolContext{Protocol:TLSv1.2}, ProtocolContext{Algorithm:X25519}, "
                                    + "ProtocolContext{Algorithm:ECDSA+SHA256}, ProtocolContext{ValueAction:TLS}]",
                            "TLS:TLSv1.2[CipherSuiteCollection:[CipherSuite:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384[AssetCollection:[KeyAgreement:ECDH[Oid:1.3.132.1.12], "
                                    + "AuthenticatedEncryption:AES-256-GCM[BlockSize:128, KeyLength:256, Mode:GCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.46], "
                                    + "PublicKeyEncryption:RSA[MessageDigest:SHA-384[BlockSize:1024, "
                                    + "Digest:DIGEST, DigestSize:384, Oid:2.16.840.1.101.3.4.2.2], "
                                    + "Oid:1.2.840.113549.1.1.1]], IdentifierCollection:[Identifier:0xC0, "
                                    + "Identifier:0x30]], "
                                    + "CipherSuite:TLS_AES_256_GCM_SHA384[AssetCollection:[AuthenticatedEncryption:AES-256-GCM[BlockSize:128, "
                                    + "KeyLength:256, Mode:GCM, Oid:2.16.840.1.101.3.4.1.46], "
                                    + "MessageDigest:SHA-384[BlockSize:1024, Digest:DIGEST, DigestSize:384, "
                                    + "Oid:2.16.840.1.101.3.4.2.2]], IdentifierCollection:[Identifier:0x13, "
                                    + "Identifier:0x02]]], "
                                    + "MergeableCollection:[KeyAgreement:x25519[EllipticCurve:Curve25519, "
                                    + "Oid:1.3.101.110], Signature:ECDSA], Version:1.2]"),
                    // 13: SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
                    finding(
                            "ProtocolContext{}[ProtocolContext{}[ProtocolContext{CipherSuite:TLS_AES_128_GCM_SHA256}, "
                                    + "ProtocolContext{Algorithm:X25519}], ProtocolContext{ValueAction:TLS}]",
                            "TLS:TLS[CipherSuiteCollection:[CipherSuite:TLS_AES_128_GCM_SHA256[AssetCollection:[AuthenticatedEncryption:AES-128-GCM[BlockSize:128, "
                                    + "KeyLength:128, Mode:GCM, Oid:2.16.840.1.101.3.4.1.6], "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]], IdentifierCollection:[Identifier:0x13, "
                                    + "Identifier:0x01]]], "
                                    + "MergeableCollection:[KeyAgreement:x25519[EllipticCurve:Curve25519, "
                                    + "Oid:1.3.101.110]]]"),
                    // 20: SSL_CTX *ctx = SSL_CTX_new_ex(libctx, NULL, DTLSv1_2_method());
                    finding(
                            "ProtocolContext{}[ProtocolContext{}[KeyContext{ValueAction:DH-2048-256}], "
                                    + "ProtocolContext{ValueAction:DTLSv1.2}]",
                            "TLS:DTLSv1.2[PublicKeyEncryption:FFDH-2048[KeyLength:2048, "
                                    + "Oid:1.2.840.113549.1.3.1], Version:1.2]"),
                    // 26: SSL_CTX *ctx = SSL_CTX_new(TLS_method());
                    finding(
                            "ProtocolContext{}[ProtocolContext{CipherSuite:AES128-GCM-SHA256}, "
                                    + "ProtocolContext{Protocol:TLSv1.2}, ProtocolContext{Protocol:TLSv1.3}, "
                                    + "ProtocolContext{ValueAction:TLS}]",
                            "TLS:TLSv1.2[CipherSuiteCollection:[CipherSuite:TLS_RSA_WITH_AES_128_GCM_SHA256[AssetCollection:[KeyAgreement:RSA[Oid:1.2.840.113549.1.1.1], "
                                    + "AuthenticatedEncryption:AES-128-GCM[BlockSize:128, KeyLength:128, Mode:GCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.6], "
                                    + "PublicKeyEncryption:RSA[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], Oid:1.2.840.113549.1.1.1]], "
                                    + "IdentifierCollection:[Identifier:0x00, Identifier:0x9C]]], Version:1.2]",
                            "TLS:TLSv1.3[CipherSuiteCollection:[CipherSuite:TLS_RSA_WITH_AES_128_GCM_SHA256[AssetCollection:[KeyAgreement:RSA[Oid:1.2.840.113549.1.1.1], "
                                    + "AuthenticatedEncryption:AES-128-GCM[BlockSize:128, KeyLength:128, Mode:GCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.6], "
                                    + "PublicKeyEncryption:RSA[MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], Oid:1.2.840.113549.1.1.1]], "
                                    + "IdentifierCollection:[Identifier:0x00, Identifier:0x9C]]], Version:1.3]"),
                    // 33: SSL_CTX *ctx = SSL_CTX_new(TLS_method());
                    finding(
                            "ProtocolContext{}[ProtocolContext{}[ProtocolContext{ValueAction:TLSv1.2}], "
                                    + "ProtocolContext{ValueAction:TLS}]",
                            "TLS:TLSv1.2[Version:1.2]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/ssl/OpenSSLSslContextTestFile.cc", this);
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
