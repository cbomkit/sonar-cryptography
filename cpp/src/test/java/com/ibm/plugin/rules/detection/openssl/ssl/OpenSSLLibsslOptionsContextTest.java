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
 * The options set on a TLS context add up: the protocol versions disabled by every {@code
 * SSL_CTX_set_options} made on a context, and by every {@code SSL_set_options} made on a connection
 * created from it, together bound the range of versions the context uses, with its minimum and
 * maximum versions. A context is so reported with the minimum and the maximum version of that
 * range, not with a version for each call; a context whose method is of one version keeps it.
 */
class OpenSSLLibsslOptionsContextTest extends TestBase {

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 4: SSL_CTX *ctx = SSL_CTX_new(TLS_method());
                    finding(
                            "ProtocolContext{}[ProtocolContext{Protocol:TLSv1.0, Protocol:TLSv1.1}, "
                                    + "ProtocolContext{ValueAction:TLS}]",
                            "TLS:TLSv1.2[Version:1.2]"),
                    // 12: SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
                    finding(
                            "ProtocolContext{}[ProtocolContext{Protocol:TLSv1.0, Protocol:TLSv1.3}, "
                                    + "ProtocolContext{ValueAction:TLS}]",
                            "TLS:TLSv1.1[Version:1.1]",
                            "TLS:TLSv1.2[Version:1.2]"),
                    // 19: SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
                    finding(
                            "ProtocolContext{}[ProtocolContext{Protocol:TLSv1.0:TLSv1.1}, "
                                    + "ProtocolContext{}[ProtocolContext{Protocol:TLSv1.2}], "
                                    + "ProtocolContext{ValueAction:TLS}]",
                            "TLS:TLSv1.3[Version:1.3]"),
                    // 27: SSL_CTX *ctx = SSL_CTX_new(TLS_method());
                    finding(
                            "ProtocolContext{}[ProtocolContext{Protocol:TLSv1.2}, "
                                    + "ProtocolContext{Protocol:TLSv1.0, Protocol:TLSv1.1}, "
                                    + "ProtocolContext{ValueAction:TLS}]",
                            "TLS:TLSv1.2[Version:1.2]"),
                    // 35: SSL_CTX *ctx = SSL_CTX_new(TLS_method());
                    finding("ProtocolContext{}[ProtocolContext{ValueAction:TLS}]", "TLS:TLS"),
                    // 41: SSL_CTX *ctx = SSL_CTX_new(TLS_method());
                    finding(
                            "ProtocolContext{}[ProtocolContext{Protocol:TLSv1.2}, "
                                    + "ProtocolContext{Protocol:TLSv1.0}, "
                                    + "ProtocolContext{ValueAction:TLS}]",
                            "TLS:TLSv1.2[Version:1.2]"),
                    // 48: SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_method());
                    finding(
                            "ProtocolContext{}[ProtocolContext{Protocol:TLSv1.0}, "
                                    + "ProtocolContext{ValueAction:TLSv1.2}]",
                            "TLS:TLSv1.2[Version:1.2]"));

    private int findings = 0;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/ssl/OpenSSLLibsslOptionsContextTestFile.cc", this);
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
