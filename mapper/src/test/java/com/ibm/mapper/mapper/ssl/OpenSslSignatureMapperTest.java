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
package com.ibm.mapper.mapper.ssl;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

public class OpenSslSignatureMapperTest {

    private static final DetectionLocation TEST_LOCATION =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

    @Test
    public void legacyAlgPlusHashFormResolvesToTheAlgorithm() {
        final OpenSslSignatureMapper mapper = new OpenSslSignatureMapper();
        final Optional<? extends INode> node = mapper.parse("ECDSA+SHA256", TEST_LOCATION);

        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(ECDSA.class);
    }

    @Test
    public void bareUppercaseNameResolvesToTheAlgorithm() {
        final OpenSslSignatureMapper mapper = new OpenSslSignatureMapper();
        assertThat(mapper.parse("ED25519", TEST_LOCATION).get()).isInstanceOf(Ed25519.class);
        assertThat(mapper.parse("RSA-PSS", TEST_LOCATION).get())
                .isInstanceOf(ProbabilisticSignatureScheme.class);
    }

    @Test
    public void tls13RsaPssWireFormatNameResolvesToRsaPss() {
        final OpenSslSignatureMapper mapper = new OpenSslSignatureMapper();
        final Optional<? extends INode> node = mapper.parse("rsa_pss_rsae_sha256", TEST_LOCATION);

        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(ProbabilisticSignatureScheme.class);
    }

    @Test
    public void tls13RsaPssPssWireFormatNameResolvesToRsaPss() {
        final OpenSslSignatureMapper mapper = new OpenSslSignatureMapper();
        assertThat(mapper.parse("rsa_pss_pss_sha384", TEST_LOCATION).get())
                .isInstanceOf(ProbabilisticSignatureScheme.class);
    }

    @Test
    public void tls12RsaPkcs1WireFormatNameResolvesToRsa() {
        final OpenSslSignatureMapper mapper = new OpenSslSignatureMapper();
        assertThat(mapper.parse("rsa_pkcs1_sha256", TEST_LOCATION).get()).isInstanceOf(RSA.class);
    }

    @Test
    public void tls13EcdsaWireFormatNameResolvesToEcdsa() {
        final OpenSslSignatureMapper mapper = new OpenSslSignatureMapper();
        final Optional<? extends INode> node =
                mapper.parse("ecdsa_secp256r1_sha256", TEST_LOCATION);

        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(ECDSA.class);
    }

    @Test
    public void rsaWithAHashIsAPkcs1v15SignatureWithThatDigest() {
        final OpenSslSignatureMapper mapper = new OpenSslSignatureMapper();
        assertThat(mapper.parse("RSA+SHA1", TEST_LOCATION).map(INode::asString))
                .contains("RSA-PKCS1-1.5-SHA-1");
        assertThat(mapper.parse("rsa_pkcs1_sha256", TEST_LOCATION).map(INode::asString))
                .contains("RSA-PKCS1-1.5-SHA-256");
    }

    @Test
    public void rsaPssWithAHashIsAnRsaPssSignatureWithThatDigest() {
        final OpenSslSignatureMapper mapper = new OpenSslSignatureMapper();
        for (String name : List.of("RSA-PSS+SHA256", "rsa_pss_rsae_sha256", "rsa_pss_pss_sha256")) {
            final INode node = mapper.parse(name, TEST_LOCATION).orElseThrow();
            assertThat(node.is(ProbabilisticSignatureScheme.class)).as(name).isTrue();
            assertThat(node.hasChildOfType(MessageDigest.class).map(INode::asString))
                    .as(name)
                    .contains("SHA-256");
        }
    }

    @Test
    public void ecdsaWireFormatNameHasItsCurveAndDigest() {
        final OpenSslSignatureMapper mapper = new OpenSslSignatureMapper();
        final INode node = mapper.parse("ecdsa_secp384r1_sha384", TEST_LOCATION).orElseThrow();

        assertThat(node).isInstanceOf(ECDSA.class);
        assertThat(node.hasChildOfType(EllipticCurve.class).map(INode::asString))
                .contains("secp384r1");
        assertThat(node.hasChildOfType(MessageDigest.class).map(INode::asString))
                .contains("SHA-384");
    }

    @Test
    public void ecdsaAndDsaWithAHashHaveThatDigest() {
        final OpenSslSignatureMapper mapper = new OpenSslSignatureMapper();
        for (String name : List.of("ECDSA+SHA256", "ecdsa_sha1", "DSA+SHA256")) {
            final INode node = mapper.parse(name, TEST_LOCATION).orElseThrow();
            assertThat(node.is(Signature.class)).as(name).isTrue();
            assertThat(node.hasChildOfType(MessageDigest.class)).as(name).isPresent();
        }
    }

    @Test
    public void mlDsaNameHasItsParameterSet() {
        final OpenSslSignatureMapper mapper = new OpenSslSignatureMapper();
        assertThat(mapper.parse("mldsa65", TEST_LOCATION).map(INode::asString))
                .contains("ML-DSA-65");
    }

    @Test
    public void unknownNameResolvesToEmpty() {
        final OpenSslSignatureMapper mapper = new OpenSslSignatureMapper();
        assertThat(mapper.parse("NOT-A-REAL-SIGALG", TEST_LOCATION)).isEmpty();
    }
}
