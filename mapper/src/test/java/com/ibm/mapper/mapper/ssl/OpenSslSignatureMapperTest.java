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

import com.ibm.mapper.model.INode;
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
        assertThat(mapper.parse("RSA-PSS", TEST_LOCATION).get()).isInstanceOf(RSA.class);
    }

    @Test
    public void tls13RsaPssWireFormatNameResolvesToRsa() {
        final OpenSslSignatureMapper mapper = new OpenSslSignatureMapper();
        final Optional<? extends INode> node = mapper.parse("rsa_pss_rsae_sha256", TEST_LOCATION);

        assertThat(node).isPresent();
        assertThat(node.get()).isInstanceOf(RSA.class);
    }

    @Test
    public void tls13RsaPssPssWireFormatNameResolvesToRsa() {
        final OpenSslSignatureMapper mapper = new OpenSslSignatureMapper();
        assertThat(mapper.parse("rsa_pss_pss_sha384", TEST_LOCATION).get()).isInstanceOf(RSA.class);
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
    public void unknownNameResolvesToEmpty() {
        final OpenSslSignatureMapper mapper = new OpenSslSignatureMapper();
        assertThat(mapper.parse("NOT-A-REAL-SIGALG", TEST_LOCATION)).isEmpty();
    }
}
