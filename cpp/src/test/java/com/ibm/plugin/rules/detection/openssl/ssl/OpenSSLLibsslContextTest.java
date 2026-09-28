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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.IProperty;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * The protocol method, the DH and EC keys and the settings of a TLS context are each reported once:
 * passing a method to {@code SSL_CTX_new} or {@code SSL_CTX_set_ssl_version}, or a key to {@code
 * SSL_CTX_set_tmp_dh}/{@code SSL_CTX_set_tmp_ecdh}, does not report them again. {@code
 * SSL_CONF_cmd} values are read according to their command, and SRTP profiles are reported with
 * their algorithms.
 */
class OpenSSLLibsslContextTest extends TestBase {

    private final List<String> assets = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/ssl/OpenSSLLibsslContextTestFile.cc", this);
        assertThat(assets)
                .containsExactly(
                        "TLS:TLS",
                        "TLS:TLSv1.2",
                        "TLS:TLS [CipherSuiteCollection:[TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]]",
                        "AssetCollection:[x25519, ECDH]",
                        "TLS:TLS",
                        "PublicKeyEncryption:FFDH-2048",
                        "PublicKeyEncryption:EC-secp256r1",
                        "TLS:TLSv1.2",
                        "TLS:TLS",
                        "TLS:TLSv1.2",
                        "TLS:TLS [CipherSuiteCollection:[TLS_RSA_WITH_AES_256_GCM_SHA384]]",
                        "AssetCollection:[x25519]",
                        "Protocol:SRTP [CipherSuiteCollection:[SRTP_AES128_CM_SHA1_80]]",
                        "AssetCollection:[ECDSA, RSA]",
                        "TLS:TLSv1.3",
                        "TLS:TLS [CipherSuiteCollection:[TLS_AES_128_GCM_SHA256]]");
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
        nodes.forEach(node -> assets.add(describe(node)));
    }

    /**
     * The kind and name of the node, followed by the kinds and names of its non-property children.
     */
    @Nonnull
    private static String describe(@Nonnull INode node) {
        final String children =
                node.getChildren().values().stream()
                        .filter(child -> !(child instanceof IProperty))
                        .map(child -> child.getKind().getSimpleName() + ":" + child.asString())
                        .sorted()
                        .collect(Collectors.joining(", "));
        final String self = node.getKind().getSimpleName() + ":" + node.asString();
        return children.isEmpty() ? self : self + " [" + children + "]";
    }
}
