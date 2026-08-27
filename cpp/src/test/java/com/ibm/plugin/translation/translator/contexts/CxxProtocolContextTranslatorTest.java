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
package com.ibm.plugin.translation.translator.contexts;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.CipherSuite;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.Protocol;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class CxxProtocolContextTranslatorTest {

    private static final DetectionLocation TEST_LOCATION =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");

    private final CxxProtocolContextTranslator translator = new CxxProtocolContextTranslator();

    private Optional<INode> translate(IValue<AstNode> value, ProtocolContext.Kind kind) {
        return translator.translate(
                () -> "OpenSSL", value, new ProtocolContext(kind), TEST_LOCATION);
    }

    @Test
    void aNonOpenSslBundleIsIgnored() {
        Optional<INode> node =
                translator.translate(
                        () -> "NotOpenSSL",
                        new ValueAction<>("TLSv1.2", (AstNode) null),
                        new ProtocolContext(ProtocolContext.Kind.TLS),
                        TEST_LOCATION);
        assertThat(node).isEmpty();
    }

    @Test
    void protocolValueUnderTlsKindResolvesToATlsNodeWithItsParsedVersion() {
        Optional<INode> node =
                translate(new Protocol<>("TLSv1.2", (AstNode) null), ProtocolContext.Kind.TLS);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(TLS.class);
        assertThat(node.get().asString()).isEqualTo("TLSv1.2");
    }

    @Test
    void protocolValueWithAnUnparsableVersionStillResolvesToABareTlsNode() {
        Optional<INode> node =
                translate(
                        new Protocol<>("garbage-version", (AstNode) null),
                        ProtocolContext.Kind.TLS);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(TLS.class);
    }

    @Test
    void protocolValueUnderANonTlsKindResolvesToAGenericProtocolNode() {
        Optional<INode> node =
                translate(new Protocol<>("QUIC", (AstNode) null), ProtocolContext.Kind.NONE);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(com.ibm.mapper.model.Protocol.class);
        assertThat(node.get().asString()).isEqualTo("QUIC");
    }

    @Test
    void cipherSuiteValueUnderTlsKindIsParsedByTheCipherSuiteMapper() {
        Optional<INode> node =
                translate(
                        new CipherSuite<>("TLS_AES_128_GCM_SHA256", (AstNode) null),
                        ProtocolContext.Kind.TLS);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(com.ibm.mapper.model.CipherSuite.class);
        assertThat(node.get().asString()).isEqualTo("TLS_AES_128_GCM_SHA256");
    }

    @Test
    void cipherSuiteValueUnderANonTlsKindResolvesToAGenericCipherSuiteNode() {
        Optional<INode> node =
                translate(new CipherSuite<>("FOO", (AstNode) null), ProtocolContext.Kind.NONE);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(com.ibm.mapper.model.CipherSuite.class);
        assertThat(node.get().asString()).isEqualTo("FOO");
    }

    @Test
    void algorithmValueUnderTlsSignatureAlgorithmsKindResolvesToAnAssetCollection() {
        Optional<INode> node =
                translate(
                        new Algorithm<>("ECDSA+SHA256", (AstNode) null),
                        ProtocolContext.Kind.TLS_SIGNATURE_ALGORITHMS);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(AssetCollection.class);
    }

    @Test
    void algorithmValueUnderTlsGroupsKindResolvesToAnAssetCollection() {
        Optional<INode> node =
                translate(
                        new Algorithm<>("X25519:P-256", (AstNode) null),
                        ProtocolContext.Kind.TLS_GROUPS);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(AssetCollection.class);
    }

    @Test
    void anEmptyAlgorithmListUnderTlsGroupsKindResolvesToEmpty() {
        Optional<INode> node =
                translate(new Algorithm<>("", (AstNode) null), ProtocolContext.Kind.TLS_GROUPS);
        assertThat(node).isEmpty();
    }

    @Test
    void algorithmValueUnderANonListKindResolvesToAGenericProtocolNode() {
        Optional<INode> node =
                translate(new Algorithm<>("FOO", (AstNode) null), ProtocolContext.Kind.NONE);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(com.ibm.mapper.model.Protocol.class);
        assertThat(node.get().asString()).isEqualTo("FOO");
    }

    @Test
    void valueActionStartingWithTlsUnderTlsKindResolvesToATlsNode() {
        Optional<INode> node =
                translate(new ValueAction<>("TLSv1.3", (AstNode) null), ProtocolContext.Kind.TLS);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(TLS.class);
        assertThat(node.get().asString()).isEqualTo("TLSv1.3");
    }

    @Test
    void valueActionNotStartingWithTlsUnderTlsKindFallsThroughToAGenericProtocolNode() {
        // SSLv3/DTLS* share ProtocolContext.Kind.TLS but do not start with "tls"
        Optional<INode> sslNode =
                translate(new ValueAction<>("SSLv3", (AstNode) null), ProtocolContext.Kind.TLS);
        assertThat(sslNode).isPresent();
        assertThat(sslNode.get()).isInstanceOf(com.ibm.mapper.model.Protocol.class);
        assertThat(sslNode.get().asString()).isEqualTo("SSLv3");

        Optional<INode> dtlsNode =
                translate(new ValueAction<>("DTLSv1", (AstNode) null), ProtocolContext.Kind.TLS);
        assertThat(dtlsNode).isPresent();
        assertThat(dtlsNode.get()).isInstanceOf(com.ibm.mapper.model.Protocol.class);
        assertThat(dtlsNode.get().asString()).isEqualTo("DTLSv1");
    }

    @Test
    void valueActionUnderANonTlsKindResolvesToAGenericProtocolNode() {
        Optional<INode> node =
                translate(new ValueAction<>("FOO", (AstNode) null), ProtocolContext.Kind.NONE);
        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(com.ibm.mapper.model.Protocol.class);
        assertThat(node.get().asString()).isEqualTo("FOO");
    }
}
