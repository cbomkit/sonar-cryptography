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
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.collections.AssetCollection;
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
 * Covers all 62 rule entries in {@link OpenSSLLibssl}.
 *
 * <p>Three finding shapes occur:
 *
 * <ul>
 *   <li><b>Generic protocol</b> ({@link Protocol}): flat — value string only, no children.
 *   <li><b>Versioned TLS</b> ({@link TLS}): wraps a {@link Version} child with dotted version.
 *   <li><b>Traced key/curve</b> ({@link KeyContext}): SSL_(CTX_)set_tmp_dh/ecdh raise no finding on
 *       the call itself; their argument is traced back to its constructing call.
 * </ul>
 */
class OpenSSLLibsslTest extends TestBase {

    private final List<String> observed = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/ssl/OpenSSLLibsslTestFile.cc", this);

        // SSL_CTX_new/SSL_CTX_set_ssl_version/SSL_set_ssl_method trace their SSL_METHOD* argument
        // back to the constructing *_method() call (see methodRules()); an untraceable NULL
        // argument resolves to no finding instead of a generic "TLS" marker.
        assertObservedCount("TLS", 3);
        assertObservedCount("SSLv3.0", 3);
        assertObservedCount("DTLS", 3);
        assertObservedCount("DTLSv1.2", 3);
        assertObservedCount("DTLSv1.0", 3);
        assertObservedCount("QUIC", 3);
        assertObservedCount("TLS-CIPHER-CONFIG", 2);
        assertObservedCount("TLS1.3-CIPHER-CONFIG", 2);
        assertObservedCount("SRTP_AES128_CM_SHA1_80", 2);

        // TLS1_2_VERSION/TLS1_3_VERSION are declared as a local enum in the fixture (no real
        // headers expanded) so OpenSSLNidLookupFactory can resolve them.
        assertObservedCount("TLSv1.0", 3);
        assertObservedCount("TLSv1.1", 3);
        // TLSv1_2_method x3, SSL_CTX_set_min_proto_version, SSL_set_min_proto_version, plus the
        // direct tls12_method = TLSv1_2_method() call and the traced SSL_CTX_new(tls12_method)
        // finding, counted separately.
        assertObservedCount("TLSv1.2", 7);
        // SSL_CTX_set_max_proto_version, SSL_set_max_proto_version, SSL_CONF_cmd.
        assertObservedCount("TLSv1.3", 3);

        assertObservedCount("SLH-DSA-SHA2-256s:ECDSA+SHA256:RSA+SHA256", 1);
        assertObservedCount("MLKEM768:X25519:secp256r1", 1);
        assertObservedCount("ECDSA+SHA256", 1);
        assertObservedCount("X25519", 1);
        // "FRODOKEM976AES" is an unrecognized group entry mixed into a known list, dropped by
        // OpenSslGroupMapper (see assertAlgorithmCollection).
        assertObservedCount("X25519:FRODOKEM976AES:secp256r1", 1);

        assertThat(observed).hasSize(45);
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
        IValue<AstNode> value = detectionStore.getDetectionValues().get(0);
        String v = value.asString();

        // SSL_(CTX_)set_tmp_dh/ecdh raise no finding on the call itself; their dh/ecdh argument is
        // traced back to its constructing call (see OpenSSLLegacyDh/OpenSSLLegacyEc), surfacing
        // here as its own KeyContext entry.
        if (detectionStore.getDetectionValueContext() instanceof KeyContext) {
            switch (v) {
                // CxxKeyContextTranslator has no case for "DH-2048-256" (a named-group
                // marker, not a key) → empty nodes, same as OpenSSLLegacyDhTest.
                case "DH-2048-256" -> assertThat(nodes).isEmpty();
                case "EC-P256" -> assertEcdsaKey(nodes);
                default -> throw new AssertionError("Unexpected key finding: " + v);
            }
            return;
        }

        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(ProtocolContext.class);
        observed.add(v);

        switch (v) {
            case "TLS" -> assertGenericProtocol(nodes, "TLS");
            // SSL_CTX_set_max_proto_version/SSL_set_max_proto_version produce a TLS node (versioned
            // protocol); SSL_CONF_cmd(NULL, "Protocol", "TLSv1.3") produces a flat Protocol node
            // (Algorithm value, no TLS-node special-casing) — same asString(), different node kind.
            case "TLSv1.3" -> {
                if (nodes.get(0) instanceof TLS) {
                    assertTlsWithVersion(nodes, "TLSv1.3", "1.3");
                } else {
                    assertGenericProtocol(nodes, "TLSv1.3");
                }
            }
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
            case "SRTP_AES128_CM_SHA1_80" -> assertGenericProtocol(nodes, "SRTP_AES128_CM_SHA1_80");
            // Signature-algorithm / group lists: captured as an AssetCollection whose children
            // are the individual algorithms, mapped per name by OpenSslSignatureMapper /
            // OpenSslGroupMapper.
            case "SLH-DSA-SHA2-256s:ECDSA+SHA256:RSA+SHA256" ->
                    assertAlgorithmCollection(nodes, "SLH-DSA", "ECDSA", "RSA");
            case "MLKEM768:X25519:secp256r1" ->
                    assertAlgorithmCollection(nodes, "ML-KEM-768", "x25519", "ECDH");
            case "ECDSA+SHA256" -> assertAlgorithmCollection(nodes, "ECDSA");
            case "X25519" -> assertAlgorithmCollection(nodes, "x25519");
            // Unknown group name ("FRODOKEM976AES") mixed into an otherwise-known list: skipped
            // entirely - only OpenSslGroupMapper's recognized entries (x25519, secp256r1) appear.
            case "X25519:FRODOKEM976AES:secp256r1" ->
                    assertAlgorithmCollection(nodes, "x25519", "ECDH");
            default -> throw new AssertionError("Unexpected value: " + v);
        }
    }

    private static void assertEcdsaKey(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node).isInstanceOf(com.ibm.mapper.model.algorithms.ECDSA.class);
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

    /**
     * A colon-separated sigalg/group list is translated to a single {@link AssetCollection} whose
     * members are the resolved algorithm nodes (one per name).
     */
    private static void assertAlgorithmCollection(
            List<INode> nodes, String... expectedAlgorithmNames) {
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node).isInstanceOf(AssetCollection.class);
        List<String> memberNames =
                ((AssetCollection) node).getCollection().stream().map(INode::asString).toList();
        assertThat(memberNames).containsExactly(expectedAlgorithmNames);
    }
}
