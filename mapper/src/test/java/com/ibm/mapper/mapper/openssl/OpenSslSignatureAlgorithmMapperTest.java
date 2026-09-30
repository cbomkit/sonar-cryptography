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
package com.ibm.mapper.mapper.openssl;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.MD5SHA1;
import com.ibm.mapper.model.algorithms.MLDSA;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.SPHINCSPlus;
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class OpenSslSignatureAlgorithmMapperTest {

    private final DetectionLocation location =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");
    private final OpenSslSignatureAlgorithmMapper mapper = new OpenSslSignatureAlgorithmMapper();

    private INode parse(String name) {
        return mapper.parse(name, location).orElseThrow();
    }

    @Test
    void rsaWithDigest() {
        INode rsa = parse("RSA-SHA256");
        assertThat(rsa).isInstanceOf(RSA.class);
        assertThat(rsa.getKind()).isEqualTo(Signature.class);
        assertThat(rsa.getChildren().get(MessageDigest.class)).isInstanceOf(SHA2.class);
        assertThat(rsa.getChildren().get(MessageDigest.class).asString()).isEqualTo("SHA-256");
    }

    @Test
    void rsaWithTheConcatenatedTlsDigest() {
        INode rsa = parse("RSA-MD5-SHA1");
        assertThat(rsa.getChildren().get(MessageDigest.class)).isInstanceOf(MD5SHA1.class);
    }

    @Test
    void rsaPssWithDigestIsNotAPkcs1Signature() {
        INode rsaPss = parse("rsa-pss-sha384");
        assertThat(rsaPss).isInstanceOf(RSAssaPSS.class);
        assertThat(rsaPss.getChildren().get(MessageDigest.class).asString()).isEqualTo("SHA-384");
    }

    @Test
    void dsaAndEcdsaWithDigest() {
        assertThat(parse("DSA-SHA224")).isInstanceOf(DSA.class);
        assertThat(parse("DSA-SHA224").getChildren().get(MessageDigest.class).asString())
                .isEqualTo("SHA-224");
        INode ecdsa = parse("ECDSA-SHA3-256");
        assertThat(ecdsa).isInstanceOf(ECDSA.class);
        assertThat(ecdsa.getChildren().get(MessageDigest.class)).isInstanceOf(SHA3.class);
    }

    @Test
    void aSchemeWithAnUnknownDigestKeepsTheScheme() {
        INode rsa = parse("RSA-UNKNOWNDIGEST");
        assertThat(rsa).isInstanceOf(RSA.class);
        assertThat(rsa.hasChildOfType(MessageDigest.class)).isEmpty();
    }

    @Test
    void rsaSchemesSelectedByPadding() {
        assertThat(parse("RSA-PKCS1").getChildren().get(Padding.class)).isInstanceOf(PKCS1.class);
        assertThat(parse("RSA-X931").asString()).isEqualTo("ANSI X9.31");
        assertThat(parse("RSA-NO-PADDING").getKind()).isEqualTo(Signature.class);
    }

    @Test
    void edwardsAndPostQuantumSchemes() {
        assertThat(parse("ED25519")).isInstanceOf(Ed25519.class);
        assertThat(parse("ML-DSA-65")).isInstanceOf(MLDSA.class);
        INode slhDsa = parse("SLH-DSA-SHA2-128s");
        assertThat(slhDsa).isInstanceOf(SPHINCSPlus.class);
        assertThat(slhDsa.getChildren().get(ParameterSetIdentifier.class).asString())
                .isEqualTo("SHA2-128S");
    }

    @Test
    void unknownAndNullNames() {
        assertThat(mapper.parse("XYZ", location)).isEmpty();
        assertThat(mapper.parse(null, location)).isEmpty();
    }
}
