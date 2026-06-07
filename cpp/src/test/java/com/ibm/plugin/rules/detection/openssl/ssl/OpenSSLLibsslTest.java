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
import com.ibm.engine.model.IAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.Version;
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
 * Covers all 69 rule entries in {@link OpenSSLLibssl}.
 *
 * <p>Two finding shapes occur:
 *
 * <ul>
 *   <li><b>Generic protocol</b> ({@link Protocol}): flat — value string only, no children.
 *   <li><b>Versioned TLS</b> ({@link TLS}): wraps a {@link Version} child with dotted version.
 * </ul>
 */
class OpenSSLLibsslTest extends TestBase {

    private final List<String> observed = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/ssl/OpenSSLLibsslTestFile.cc", this);

        assertObservedCount(
                "TLS",
                6); // TLS_method x3, SSL_CTX_new, SSL_CTX_set_ssl_version, SSL_set_ssl_method
        assertObservedCount("SSLv3.0", 3);
        assertObservedCount("DTLS", 3);
        assertObservedCount("DTLSv1.2", 3);
        assertObservedCount("DTLSv1.0", 3);
        assertObservedCount("QUIC", 3);
        assertObservedCount("TLS-CIPHER-CONFIG", 2);
        assertObservedCount("TLS1.3-CIPHER-CONFIG", 2);
        assertObservedCount("TLS-DH-PARAMS", 2); // SSL_CTX_set0_tmp_dh_pkey, SSL_set0_tmp_dh_pkey
        assertObservedCount("TLS-CONF-CMD", 1);
        assertObservedCount("SRTP-PROFILE", 2);

        // Versioned TLS findings
        assertObservedCount("TLSv1.2", 3);
        assertObservedCount("TLSv1.1", 3);
        assertObservedCount("TLSv1.0", 3);

        assertThat(observed).hasSize(39);
    }

    private void assertObservedCount(String value, int expected) {
        long count = observed.stream().filter(v -> v.equals(value)).count();
        assertThat(count)
                .as("Expected %d occurrences of '%s' but found %d", expected, value, count)
                .isEqualTo(expected);
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
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(ProtocolContext.class);
        IValue<AstNode> value = detectionStore.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(IAction.class);

        String v = value.asString();
        observed.add(v);

        switch (v) {
            case "TLS" -> assertGenericProtocol(nodes, "TLS");
            case "TLSv1.2" -> assertTlsWithVersion(nodes, "TLSv1.2", "1.2");
            case "TLSv1.1" -> assertTlsWithVersion(nodes, "TLSv1.1", "1.1");
            case "TLSv1.0" -> assertTlsWithVersion(nodes, "TLSv1.0", "1.0");
            case "SSLv3.0" -> assertGenericProtocol(nodes, "SSLv3.0");
            case "DTLS" -> assertGenericProtocol(nodes, "DTLS");
            case "DTLSv1.2" -> assertGenericProtocol(nodes, "DTLSv1.2");
            case "DTLSv1.0" -> assertGenericProtocol(nodes, "DTLSv1.0");
            case "QUIC" -> assertGenericProtocol(nodes, "QUIC");
            case "TLS-CIPHER-CONFIG" -> assertGenericProtocol(nodes, "TLS-CIPHER-CONFIG");
            case "TLS1.3-CIPHER-CONFIG" -> assertGenericProtocol(nodes, "TLS1.3-CIPHER-CONFIG");
            case "TLS-GROUPS-CONFIG" -> assertGenericProtocol(nodes, "TLS-GROUPS-CONFIG");
            case "TLS-SIGALGS-CONFIG" -> assertGenericProtocol(nodes, "TLS-SIGALGS-CONFIG");
            case "TLS-DH-PARAMS" -> assertGenericProtocol(nodes, "TLS-DH-PARAMS");
            case "TLS-ECDH-PARAMS" -> assertGenericProtocol(nodes, "TLS-ECDH-PARAMS");
            case "TLS-CONF-CMD" -> assertGenericProtocol(nodes, "TLS-CONF-CMD");
            case "SRTP-PROFILE" -> assertGenericProtocol(nodes, "SRTP-PROFILE");
            default -> throw new AssertionError("Unexpected value: " + v);
        }
    }

    private static void assertGenericProtocol(List<INode> nodes, String expected) {
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node).isInstanceOf(Protocol.class);
        assertThat(node).isNotInstanceOf(TLS.class);
        assertThat(node.asString()).isEqualTo(expected);
        assertThat(node.hasChildren()).isFalse();
    }

    private static void assertTlsWithVersion(
            List<INode> nodes, String expectedAsString, String expectedVersion) {
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node).isInstanceOf(TLS.class);
        assertThat(node.asString()).isEqualTo(expectedAsString);
        INode version = node.getChildren().get(Version.class);
        assertThat(version).isNotNull();
        assertThat(version.asString()).isEqualTo(expectedVersion);
    }
}
