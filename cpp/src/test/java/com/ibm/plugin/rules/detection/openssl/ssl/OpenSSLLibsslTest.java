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
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
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

    private final List<String> observed = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/openssl/ssl/OpenSSLLibsslTestFile.cc", this);

        // one per *_method() call; SSL_CTX_new/SSL_CTX_set_ssl_version/SSL_set_ssl_method do not
        // report the method again
        assertObservedCount("TLS", 3);
        assertObservedCount("SSLv3.0", 3);
        assertObservedCount("DTLS", 3);
        assertObservedCount("DTLSv1.2", 3);
        assertObservedCount("DTLSv1.0", 3);
        assertObservedCount("QUIC", 3);
        assertObservedCount("HIGH", 2);
        assertObservedCount("TLS_AES_128_GCM_SHA256", 2);
        assertObservedCount("SRTP_AES128_CM_SHA1_80", 2);

        // TLS1_2_VERSION/TLS1_3_VERSION are declared as a local enum in the fixture (no real
        // headers expanded) so OpenSSLNidLookupFactory can resolve them.
        assertObservedCount("TLSv1.0", 3);
        assertObservedCount("TLSv1.1", 3);
        // TLSv1_2_method x3, SSL_CTX_set_min_proto_version, SSL_set_min_proto_version, and the
        // tls12_method = TLSv1_2_method() call passed to SSL_CTX_new.
        assertObservedCount("TLSv1.2", 6);
        // SSL_CTX_set_max_proto_version, SSL_set_max_proto_version. SSL_CONF_cmd's "Protocol"
        // command enables and disables versions and is not reported.
        assertObservedCount("TLSv1.3", 2);

        assertObservedCount("SLH-DSA-SHA2-256s:ECDSA+SHA256:RSA+SHA256", 1);
        assertObservedCount("MLKEM768:X25519:secp256r1", 1);
        assertObservedCount("ECDSA+SHA256", 1);
        assertObservedCount("X25519", 1);
        // "FRODOKEM976AES" is an unrecognized group name mixed into a known list (see
        // assertAlgorithmCollection).
        assertObservedCount("X25519:FRODOKEM976AES:secp256r1", 1);

        assertThat(observed).hasSize(43);
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

        // the DH and EC keys passed to SSL_(CTX_)set_tmp_dh/ecdh, reported where they are created
        // (see OpenSSLLegacyDh/OpenSSLLegacyEc)
        if (detectionStore.getDetectionValueContext() instanceof KeyContext) {
            switch (v) {
                // RFC 5114 group from DH_get_2048_256()
                case "DH-2048-256" -> {
                    assertThat(nodes).hasSize(1);
                    assertThat(nodes.get(0).asString()).isEqualTo("FFDH-2048");
                }
                case "EC-P256" -> assertEcKey(nodes);
                default -> throw new AssertionError("Unexpected key finding: " + v);
            }
            return;
        }

        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(ProtocolContext.class);
        observed.add(v);

        switch (v) {
            case "TLS" -> {
                assertThat(nodes).singleElement().isInstanceOf(TLS.class);
                assertThat(nodes.get(0).hasChildOfType(Version.class)).isEmpty();
            }
            case "TLSv1.3" -> assertTlsWithVersion(nodes, "TLSv1.3", "1.3");
            case "TLSv1.2" -> assertTlsWithVersion(nodes, "TLSv1.2", "1.2");
            case "TLSv1.1" -> assertTlsWithVersion(nodes, "TLSv1.1", "1.1");
            case "TLSv1.0" -> assertTlsWithVersion(nodes, "TLSv1.0", "1.0");
            case "SSLv3.0" -> assertTlsWithVersion(nodes, "SSLv3.0", "3.0");
            case "DTLS" -> assertGenericProtocol(nodes, "DTLS");
            case "DTLSv1.2" -> assertTlsWithVersion(nodes, "DTLSv1.2", "1.2");
            case "DTLSv1.0" -> assertTlsWithVersion(nodes, "DTLSv1.0", "1.0");
            case "QUIC" -> assertGenericProtocol(nodes, "QUIC");
            // a cipher string holding only a keyword names no single cipher suite
            case "HIGH" -> assertThat(nodes).isEmpty();
            case "TLS_AES_128_GCM_SHA256" -> {
                assertThat(nodes).hasSize(1);
                assertThat(((TLS) nodes.get(0)).getCipherSuits().orElseThrow().getCollection())
                        .singleElement()
                        .isInstanceOf(CipherSuite.class)
                        .extracting(INode::asString)
                        .isEqualTo("TLS_AES_128_GCM_SHA256");
            }
            case "SRTP_AES128_CM_SHA1_80" -> {
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).asString()).isEqualTo("SRTP");
                assertThat(nodes.get(0).hasChildOfType(CipherSuiteCollection.class))
                        .get()
                        .extracting(INode::asString)
                        .isEqualTo("[SRTP_AES128_CM_SHA1_80]");
            }
            // Signature-algorithm / group lists: captured as an AssetCollection whose children
            // are the individual algorithms, mapped per name by OpenSslSignatureMapper /
            // OpenSslGroupMapper.
            case "SLH-DSA-SHA2-256s:ECDSA+SHA256:RSA+SHA256" ->
                    assertAlgorithmCollection(nodes, "SLH-DSA", "ECDSA", "RSA");
            case "MLKEM768:X25519:secp256r1" ->
                    assertAlgorithmCollection(nodes, "ML-KEM-768", "x25519", "ECDH");
            case "ECDSA+SHA256" -> assertAlgorithmCollection(nodes, "ECDSA");
            case "X25519" -> assertAlgorithmCollection(nodes, "x25519");
            // an unknown group name ("FRODOKEM976AES") in an otherwise known list is an algorithm
            // whose kind (key agreement or key encapsulation) is not known
            case "X25519:FRODOKEM976AES:secp256r1" -> {
                assertAlgorithmCollection(nodes, "x25519", "FRODOKEM976AES", "ECDH");
                assertThat(((AssetCollection) nodes.get(0)).getCollection().get(1))
                        .isInstanceOf(Algorithm.class)
                        .extracting(INode::getKind)
                        .isEqualTo(Unknown.class);
            }
            default -> throw new AssertionError("Unexpected value: " + v);
        }
    }

    private static void assertEcKey(List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node).isInstanceOf(EllipticCurveAlgorithm.class);
        assertThat(node.asString()).isEqualTo("EC-secp256r1");
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
     * A colon-separated sigalg/group list is translated to a single {@link AssetCollection} with
     * one child per name: recognized names resolve to their mapped algorithm node, unrecognized
     * names surface as a raw {@link Protocol} node.
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
