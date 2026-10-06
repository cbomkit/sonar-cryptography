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
 * A TLS context created with {@code SSL_CTX_new} is reported as one protocol, with the version of
 * its method and its configuration (versions, cipher suites, groups). The method, the DH and EC
 * keys and the settings of a context created elsewhere are each reported once: passing a method to
 * {@code SSL_CTX_set_ssl_version}, or a key to {@code SSL_CTX_set_tmp_dh}/{@code
 * SSL_CTX_set_tmp_ecdh}, does not report them again. {@code SSL_CONF_cmd} values are read according
 * to their command, and SRTP profiles are reported with their algorithms.
 */
class OpenSSLLibsslContextTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 4: SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
                    finding(
                            "ProtocolContext{}[ProtocolContext{CipherSuite:ECDHE-RSA-AES256-GCM-SHA384}, "
                                    + "ProtocolContext{Protocol:TLSv1.2}, ProtocolContext{Algorithm:X25519:P-256}, "
                                    + "ProtocolContext{ValueAction:TLS}]",
                            "TLS:TLSv1.2[CipherSuiteCollection:[CipherSuite:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384[AssetCollection:[KeyAgreement:ECDH[Oid:1.3.132.1.12], "
                                    + "AuthenticatedEncryption:AES-256-GCM[BlockSize:128, KeyLength:256, Mode:GCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.46], "
                                    + "PublicKeyEncryption:RSA[MessageDigest:SHA-384[BlockSize:1024, "
                                    + "Digest:DIGEST, DigestSize:384, Oid:2.16.840.1.101.3.4.2.2], "
                                    + "Oid:1.2.840.113549.1.1.1]], IdentifierCollection:[Identifier:0xC0, "
                                    + "Identifier:0x30]]], "
                                    + "MergeableCollection:[KeyAgreement:x25519[EllipticCurve:Curve25519, "
                                    + "Oid:1.3.101.110], KeyAgreement:ECDH[EllipticCurve:secp256r1, "
                                    + "Oid:1.3.132.1.12]], Version:1.2]"),
                    // 12: SSL_CTX *ctx = SSL_CTX_new(method);
                    finding("ProtocolContext{}[ProtocolContext{ValueAction:TLS}]", "TLS:TLS"),
                    // 16: DH *dh = DH_get_2048_256();
                    finding(
                            "KeyContext{ValueAction:DH-2048-256}",
                            "PublicKeyEncryption:FFDH-2048[KeyLength:2048, Oid:1.2.840.113549.1.3.1]"),
                    // 18: EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
                    finding(
                            "KeyContext{ValueAction:EC-prime256v1}",
                            "PublicKeyEncryption:EC-secp256r1[EllipticCurve:secp256r1, "
                                    + "Oid:1.2.840.10045.2.1]"),
                    // 23: SSL_CTX_set_ssl_version(ctx, TLSv1_2_method());
                    finding("ProtocolContext{ValueAction:TLSv1.2}", "TLS:TLSv1.2[Version:1.2]"),
                    // 24: SSL_set_ssl_method(ssl, TLS_client_method());
                    finding("ProtocolContext{ValueAction:TLS}", "TLS:TLS"),
                    // 28: SSL_CONF_cmd(cctx, "MinProtocol", "TLSv1.2");
                    finding("ProtocolContext{Protocol:TLSv1.2}", "TLS:TLSv1.2[Version:1.2]"),
                    // 29: SSL_CONF_cmd(cctx, "CipherString", "AES256-GCM-SHA384");
                    finding(
                            "ProtocolContext{CipherSuite:AES256-GCM-SHA384}",
                            "TLS:TLS[CipherSuiteCollection:[CipherSuite:TLS_RSA_WITH_AES_256_GCM_SHA384[AssetCollection:[KeyAgreement:RSA[Oid:1.2.840.113549.1.1.1], "
                                    + "AuthenticatedEncryption:AES-256-GCM[BlockSize:128, KeyLength:256, Mode:GCM, "
                                    + "Oid:2.16.840.1.101.3.4.1.46], "
                                    + "PublicKeyEncryption:RSA[MessageDigest:SHA-384[BlockSize:1024, "
                                    + "Digest:DIGEST, DigestSize:384, Oid:2.16.840.1.101.3.4.2.2], "
                                    + "Oid:1.2.840.113549.1.1.1]], IdentifierCollection:[Identifier:0x00, "
                                    + "Identifier:0x9D]]]]"),
                    // 30: SSL_CONF_cmd(cctx, "Groups", "X25519");
                    finding(
                            "ProtocolContext{Algorithm:X25519}",
                            "MergeableCollection:[KeyAgreement:x25519[EllipticCurve:Curve25519, "
                                    + "Oid:1.3.101.110]]"),
                    // 32: SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80");
                    finding(
                            "ProtocolContext{Algorithm:SRTP_AES128_CM_SHA1_80}",
                            "Protocol:SRTP[CipherSuiteCollection:[CipherSuite:SRTP_AES128_CM_SHA1_80[AssetCollection:[BlockCipher:AES-128-CTR[BlockSize:128, "
                                    + "KeyLength:128, Mode:CTR, Oid:2.16.840.1.101.3.4.1], "
                                    + "Mac:HMAC-SHA-1[MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:160, Oid:1.3.14.3.2.26], Oid:1.2.840.113549.2.7, Tag:TAG, "
                                    + "TagLength:80]], IdentifierCollection:[Identifier:0x00, Identifier:0x01]]]]"),
                    // 33: SSL_CTX_set1_sigalgs_list(ctx, "ECDSA+SHA256:RSA-PSS+SHA256");
                    finding(
                            "ProtocolContext{Algorithm:ECDSA+SHA256:RSA-PSS+SHA256}",
                            "MergeableCollection:[Signature:ECDSA-SHA-256[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.10045.4.3.2], "
                                    + "ProbabilisticSignatureScheme:RSA-PSS[MessageDigest:SHA-256[BlockSize:512, "
                                    + "Digest:DIGEST, DigestSize:256, Oid:2.16.840.1.101.3.4.2.1], "
                                    + "Oid:1.2.840.113549.1.1.10]]"),
                    // 34: SSL_set_min_proto_version(ssl, TLS1_3_VERSION);
                    finding("ProtocolContext{Protocol:TLSv1.3}", "TLS:TLSv1.3[Version:1.3]"),
                    // 35: SSL_set_ciphersuites(ssl, "TLS_AES_128_GCM_SHA256");
                    finding(
                            "ProtocolContext{CipherSuite:TLS_AES_128_GCM_SHA256}",
                            "TLS:TLS[CipherSuiteCollection:[CipherSuite:TLS_AES_128_GCM_SHA256[AssetCollection:[AuthenticatedEncryption:AES-128-GCM[BlockSize:128, "
                                    + "KeyLength:128, Mode:GCM, Oid:2.16.840.1.101.3.4.1.6], "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]], IdentifierCollection:[Identifier:0x13, "
                                    + "Identifier:0x01]]]]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/ssl/OpenSSLLibsslContextTestFile.cc", this);
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
