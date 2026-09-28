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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.ArrayList;
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

    private final List<List<String>> cipherLists = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/ssl/OpenSSLLibsslCipherListTestFile.cc", this);
        assertThat(cipherLists)
                .containsExactly(
                        List.of("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
                        List.of("TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"));
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
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(ProtocolContext.class);
        if (nodes.isEmpty()) {
            // a cipher string of keywords and exclusions only
            return;
        }
        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0)).isInstanceOf(TLS.class);
        List<String> suites = new ArrayList<>();
        for (INode suite : ((TLS) nodes.get(0)).getCipherSuits().orElseThrow().getCollection()) {
            assertThat(suite).isInstanceOf(CipherSuite.class);
            suites.add(suite.asString());
        }
        cipherLists.add(suites);
    }
}
