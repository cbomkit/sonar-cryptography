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
package com.ibm.plugin.rules.detection.openssl.macros;

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
 * Algorithm names, parameter keys, protocol versions and curve identifiers given as OpenSSL header
 * macros are detected when the headers themselves are not available to the analysis.
 */
class OpenSSLMacrosTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 6: EVP_KDF *kdf = EVP_KDF_fetch(NULL, OSSL_KDF_NAME_HKDF, NULL);
                    finding(
                            "KeyDerivationFunctionContext{Algorithm:HKDF}[KeyDerivationFunctionContext{}[DigestContext{Algorithm:SHA-256}]]",
                            "KeyDerivationFunction:HKDF-SHA-256[KeyDerivation:KEYDERIVATION, "
                                    + "MessageDigest:SHA-256[BlockSize:512, Digest:DIGEST, DigestSize:256, "
                                    + "Oid:2.16.840.1.101.3.4.2.1]]"),
                    // 16: EVP_MAC_fetch(NULL, OSSL_MAC_NAME_POLY1305, NULL);
                    finding("MacContext{Algorithm:POLY1305}", "Mac:Poly1305[Tag:TAG]"),
                    // 20: EVP_get_digestbyname(SN_sha384);
                    finding(
                            "DigestContext{Algorithm:SHA-384}",
                            "MessageDigest:SHA-384[BlockSize:1024, Digest:DIGEST, DigestSize:384, "
                                    + "Oid:2.16.840.1.101.3.4.2.2]"),
                    // 24: SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
                    finding("ProtocolContext{Protocol:TLSv1.2}", "TLS:TLSv1.2[Version:1.2]"),
                    // 28: EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
                    finding(
                            "KeyContext{ValueAction:EC-P256}",
                            "PublicKeyEncryption:EC-secp256r1[EllipticCurve:secp256r1, "
                                    + "Oid:1.2.840.10045.2.1]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/macros/OpenSSLMacrosTestFile.cc", this);
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
