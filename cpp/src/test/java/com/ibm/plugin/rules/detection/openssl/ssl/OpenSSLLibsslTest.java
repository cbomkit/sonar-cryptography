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
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.protocol.TLS;
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
 * Covers the rule entries in {@link OpenSSLLibssl}.
 *
 * <p>Finding shapes:
 *
 * <ul>
 *   <li><b>TLS</b> ({@link TLS}): with a {@link Version} child when the method or setting names a
 *       version, without one for {@code TLS_method()} and its client and server forms.
 *   <li><b>Generic protocol</b> ({@link Protocol}): DTLS and QUIC methods, flat.
 *   <li><b>SRTP</b>: a {@link Protocol} holding the configured protection profiles.
 *   <li><b>Key</b> ({@link KeyContext}): the DH and EC keys created for {@code
 *       SSL_(CTX_)set_tmp_dh/ecdh}, reported once where they are created.
 * </ul>
 */
class OpenSSLLibsslTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 8: TLS_method();
                    finding("ProtocolContext{ValueAction:TLS}", "TLS:TLS"),
                    // 9: TLS_client_method();
                    finding("ProtocolContext{ValueAction:TLS}", "TLS:TLS"),
                    // 10: TLS_server_method();
                    finding("ProtocolContext{ValueAction:TLS}", "TLS:TLS"),
                    // 12: TLSv1_2_method();
                    finding("ProtocolContext{ValueAction:TLSv1.2}", "TLS:TLSv1.2[Version:1.2]"),
                    // 13: TLSv1_2_client_method();
                    finding("ProtocolContext{ValueAction:TLSv1.2}", "TLS:TLSv1.2[Version:1.2]"),
                    // 14: TLSv1_2_server_method();
                    finding("ProtocolContext{ValueAction:TLSv1.2}", "TLS:TLSv1.2[Version:1.2]"),
                    // 16: TLSv1_1_method();
                    finding("ProtocolContext{ValueAction:TLSv1.1}", "TLS:TLSv1.1[Version:1.1]"),
                    // 17: TLSv1_1_client_method();
                    finding("ProtocolContext{ValueAction:TLSv1.1}", "TLS:TLSv1.1[Version:1.1]"),
                    // 18: TLSv1_1_server_method();
                    finding("ProtocolContext{ValueAction:TLSv1.1}", "TLS:TLSv1.1[Version:1.1]"),
                    // 20: TLSv1_method();
                    finding("ProtocolContext{ValueAction:TLSv1.0}", "TLS:TLSv1.0[Version:1.0]"),
                    // 21: TLSv1_client_method();
                    finding("ProtocolContext{ValueAction:TLSv1.0}", "TLS:TLSv1.0[Version:1.0]"),
                    // 22: TLSv1_server_method();
                    finding("ProtocolContext{ValueAction:TLSv1.0}", "TLS:TLSv1.0[Version:1.0]"),
                    // 24: SSLv3_method();
                    finding("ProtocolContext{ValueAction:SSLv3.0}", "TLS:SSLv3.0[Version:3.0]"),
                    // 25: SSLv3_client_method();
                    finding("ProtocolContext{ValueAction:SSLv3.0}", "TLS:SSLv3.0[Version:3.0]"),
                    // 26: SSLv3_server_method();
                    finding("ProtocolContext{ValueAction:SSLv3.0}", "TLS:SSLv3.0[Version:3.0]"),
                    // 28: DTLS_method();
                    finding("ProtocolContext{ValueAction:DTLS}", "Protocol:DTLS"),
                    // 29: DTLS_client_method();
                    finding("ProtocolContext{ValueAction:DTLS}", "Protocol:DTLS"),
                    // 30: DTLS_server_method();
                    finding("ProtocolContext{ValueAction:DTLS}", "Protocol:DTLS"),
                    // 32: DTLSv1_2_method();
                    finding("ProtocolContext{ValueAction:DTLSv1.2}", "TLS:DTLSv1.2[Version:1.2]"),
                    // 33: DTLSv1_2_client_method();
                    finding("ProtocolContext{ValueAction:DTLSv1.2}", "TLS:DTLSv1.2[Version:1.2]"),
                    // 34: DTLSv1_2_server_method();
                    finding("ProtocolContext{ValueAction:DTLSv1.2}", "TLS:DTLSv1.2[Version:1.2]"),
                    // 36: DTLSv1_method();
                    finding("ProtocolContext{ValueAction:DTLSv1.0}", "TLS:DTLSv1.0[Version:1.0]"),
                    // 37: DTLSv1_client_method();
                    finding("ProtocolContext{ValueAction:DTLSv1.0}", "TLS:DTLSv1.0[Version:1.0]"),
                    // 38: DTLSv1_server_method();
                    finding("ProtocolContext{ValueAction:DTLSv1.0}", "TLS:DTLSv1.0[Version:1.0]"),
                    // 40: OSSL_QUIC_client_method();
                    finding("ProtocolContext{ValueAction:QUIC}", "Protocol:QUIC"),
                    // 41: OSSL_QUIC_client_thread_method();
                    finding("ProtocolContext{ValueAction:QUIC}", "Protocol:QUIC"),
                    // 42: OSSL_QUIC_server_method();
                    finding("ProtocolContext{ValueAction:QUIC}", "Protocol:QUIC"),
                    // 47: SSL_CTX_new(tls12_method);
                    finding(
                            "ProtocolContext{}[ProtocolContext{ValueAction:TLSv1.2}]",
                            "TLS:TLSv1.2[Version:1.2]"),
                    // 50: SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256");
                    finding(
                            "ProtocolContext{CipherSuite:TLS_AES_128_GCM_SHA256}",
                            "TLS:TLS[CipherSuiteCollection:[CipherSuite:TLS_AES_128_GCM_SHA256[AssetCollection:[AuthenticatedEncryption:AES-128-GCM[BlockSize:128, "
                                    + "KeyLength:128, Mode:GCM, Oid:2.16.840.1.101.3.4.1.6], "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]], IdentifierCollection:[Identifier:0x13, "
                                    + "Identifier:0x01]]]]"),
                    // 51: SSL_set_ciphersuites(s, "TLS_AES_128_GCM_SHA256");
                    finding(
                            "ProtocolContext{CipherSuite:TLS_AES_128_GCM_SHA256}",
                            "TLS:TLS[CipherSuiteCollection:[CipherSuite:TLS_AES_128_GCM_SHA256[AssetCollection:[AuthenticatedEncryption:AES-128-GCM[BlockSize:128, "
                                    + "KeyLength:128, Mode:GCM, Oid:2.16.840.1.101.3.4.1.6], "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]], IdentifierCollection:[Identifier:0x13, "
                                    + "Identifier:0x01]]]]"),
                    // 53: DH* dh1 = DH_get_2048_256();
                    finding(
                            "KeyContext{ValueAction:DH-2048-256}",
                            "PublicKeyEncryption:FFDH-2048[KeyLength:2048, Oid:1.2.840.113549.1.3.1]"),
                    // 55: DH* dh2 = DH_get_2048_256();
                    finding(
                            "KeyContext{ValueAction:DH-2048-256}",
                            "PublicKeyEncryption:FFDH-2048[KeyLength:2048, Oid:1.2.840.113549.1.3.1]"),
                    // 57: EC_KEY* ecdh1 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
                    finding(
                            "KeyContext{ValueAction:EC-P256}",
                            "PublicKeyEncryption:EC-secp256r1[EllipticCurve:secp256r1, "
                                    + "Oid:1.2.840.10045.2.1]"),
                    // 59: EC_KEY* ecdh2 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
                    finding(
                            "KeyContext{ValueAction:EC-P256}",
                            "PublicKeyEncryption:EC-secp256r1[EllipticCurve:secp256r1, "
                                    + "Oid:1.2.840.10045.2.1]"),
                    // 66: SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80");
                    finding(
                            "ProtocolContext{Algorithm:SRTP_AES128_CM_SHA1_80}",
                            "Protocol:SRTP[CipherSuiteCollection:[CipherSuite:SRTP_AES128_CM_SHA1_80[AssetCollection:[BlockCipher:AES-128-CTR[BlockSize:128, "
                                    + "KeyLength:128, Mode:CTR, Oid:2.16.840.1.101.3.4.1], "
                                    + "Mac:HMAC-SHA-1[MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:160, Oid:1.3.14.3.2.26], Oid:1.2.840.113549.2.7, Tag:TAG, "
                                    + "TagLength:80]], IdentifierCollection:[Identifier:0x00, Identifier:0x01]]]]"),
                    // 67: SSL_set_tlsext_use_srtp(s, "SRTP_AES128_CM_SHA1_80");
                    finding(
                            "ProtocolContext{Algorithm:SRTP_AES128_CM_SHA1_80}",
                            "Protocol:SRTP[CipherSuiteCollection:[CipherSuite:SRTP_AES128_CM_SHA1_80[AssetCollection:[BlockCipher:AES-128-CTR[BlockSize:128, "
                                    + "KeyLength:128, Mode:CTR, Oid:2.16.840.1.101.3.4.1], "
                                    + "Mac:HMAC-SHA-1[MessageDigest:SHA-1[BlockSize:512, Digest:DIGEST, "
                                    + "DigestSize:160, Oid:1.3.14.3.2.26], Oid:1.2.840.113549.2.7, Tag:TAG, "
                                    + "TagLength:80]], IdentifierCollection:[Identifier:0x00, Identifier:0x01]]]]"),
                    // 75: SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
                    finding("ProtocolContext{Protocol:TLSv1.2}", "TLS:TLSv1.2[Version:1.2]"),
                    // 76: SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
                    finding("ProtocolContext{Protocol:TLSv1.3}", "TLS:TLSv1.3[Version:1.3]"),
                    // 77: SSL_set_min_proto_version(s, TLS1_2_VERSION);
                    finding("ProtocolContext{Protocol:TLSv1.2}", "TLS:TLSv1.2[Version:1.2]"),
                    // 78: SSL_set_max_proto_version(s, TLS1_3_VERSION);
                    finding("ProtocolContext{Protocol:TLSv1.3}", "TLS:TLSv1.3[Version:1.3]"),
                    // 81: SSL_CTX_set1_sigalgs_list(ctx,
                    // "SLH-DSA-SHA2-256s:ECDSA+SHA256:RSA+SHA256");
                    finding(
                            "ProtocolContext{Algorithm:SLH-DSA-SHA2-256s:ECDSA+SHA256:RSA+SHA256}",
                            "MergeableCollection:[Signature:SLH-DSA, Signature:ECDSA, "
                                    + "PublicKeyEncryption:RSA[Oid:1.2.840.113549.1.1.1]]"),
                    // 82: SSL_CTX_set1_groups_list(ctx, "MLKEM768:X25519:secp256r1");
                    finding(
                            "ProtocolContext{Algorithm:MLKEM768:X25519:secp256r1}",
                            "MergeableCollection:[KeyEncapsulationMechanism:ML-KEM-768[Oid:2.16.840.1.101.3.4.4.2, "
                                    + "ParameterSetIdentifier:768], KeyAgreement:x25519[EllipticCurve:Curve25519, "
                                    + "Oid:1.3.101.110], KeyAgreement:ECDH[EllipticCurve:secp256r1, "
                                    + "Oid:1.3.132.1.12]]"),
                    // 84: SSL_CTX_set1_client_sigalgs_list(ctx, "ECDSA+SHA256");
                    finding(
                            "ProtocolContext{Algorithm:ECDSA+SHA256}",
                            "MergeableCollection:[Signature:ECDSA]"),
                    // 85: SSL_set1_groups_list(s, "X25519");
                    finding(
                            "ProtocolContext{Algorithm:X25519}",
                            "MergeableCollection:[KeyAgreement:x25519[EllipticCurve:Curve25519, "
                                    + "Oid:1.3.101.110]]"),
                    // 86: SSL_set1_sigalgs_list(s, "ECDSA+SHA384");
                    finding(
                            "ProtocolContext{Algorithm:ECDSA+SHA384}",
                            "MergeableCollection:[Signature:ECDSA]"),
                    // 90: SSL_CTX_set1_groups_list(ctx, "X25519:FRODOKEM976AES:secp256r1");
                    finding(
                            "ProtocolContext{Algorithm:X25519:FRODOKEM976AES:secp256r1}",
                            "MergeableCollection:[KeyAgreement:x25519[EllipticCurve:Curve25519, "
                                    + "Oid:1.3.101.110], Unknown:FRODOKEM976AES, "
                                    + "KeyAgreement:ECDH[EllipticCurve:secp256r1, Oid:1.3.132.1.12]]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/ssl/OpenSSLLibsslTestFile.cc", this);
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
