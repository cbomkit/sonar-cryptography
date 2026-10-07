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
 * The groups set with {@code SSL_CTX_set1_curves_list} / {@code SSL_set1_curves_list}, aliases of
 * the {@code *_groups_list} functions, are reported. The protocol versions disabled with {@code
 * SSL_CTX_set_options} / {@code SSL_set_options} report the range of versions OpenSSL uses: the
 * lowest run of versions that are not disabled, with its lowest version when the options raise the
 * minimum and its highest when they lower the maximum, as {@code SSL_CTX_set_min_proto_version} and
 * {@code SSL_CTX_set_max_proto_version} report them. Options that disable no version report
 * nothing.
 */
class OpenSSLLibsslOptionsTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 4: SSL_CTX_set1_curves_list(ctx, "P-384");
                    finding(
                            "ProtocolContext{Algorithm:P-384}",
                            "MergeableCollection:[KeyAgreement:ECDH[EllipticCurve:secp384r1, "
                                    + "Oid:1.3.132.1.12]]"),
                    // 5: SSL_set1_curves_list(ssl, "X25519");
                    finding(
                            "ProtocolContext{Algorithm:X25519}",
                            "MergeableCollection:[KeyAgreement:x25519[EllipticCurve:Curve25519, "
                                    + "Oid:1.3.101.110]]"),
                    // 9: SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 |
                    // SSL_OP_NO_TLSv1_1);
                    finding(
                            "ProtocolContext{Protocol:TLSv1.0:TLSv1.1}",
                            "TLS:TLSv1.2[Version:1.2]"),
                    // 13: SSL_set_options(ssl, SSL_OP_NO_TLSv1_3);
                    finding("ProtocolContext{Protocol:TLSv1.3}", "TLS:TLSv1.2[Version:1.2]"),
                    // 18: SSL_CTX_set_options(ctx, options);
                    finding("ProtocolContext{Protocol:TLSv1.0}", "TLS:TLSv1.1[Version:1.1]"),
                    // 22: SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
                    finding("ProtocolContext{Protocol:TLSv1.1}", "TLS:TLSv1.0[Version:1.0]"),
                    // 26: SSL_CTX_set_options(ctx, SSL_OP_NO_DTLSv1);
                    finding("ProtocolContext{Protocol:DTLSv1.0}", "TLS:DTLSv1.2[Version:1.2]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/ssl/OpenSSLLibsslOptionsTestFile.cc", this);
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
