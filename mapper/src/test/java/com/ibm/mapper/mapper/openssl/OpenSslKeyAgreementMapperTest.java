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

import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.MLKEM;
import com.ibm.mapper.model.algorithms.SM2;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class OpenSslKeyAgreementMapperTest {

    private final DetectionLocation location =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");
    private final OpenSslKeyAgreementMapper mapper = new OpenSslKeyAgreementMapper();

    private INode parse(String name) {
        return mapper.parse(name, location).orElseThrow();
    }

    @ParameterizedTest
    @CsvSource({"DH-2048,2048", "DH-3072,3072", "dh-4096,4096"})
    void ffdheGroupsKeepTheirSize(String name, String keyLength) {
        INode dh = parse(name);
        assertThat(dh).isInstanceOf(DH.class);
        assertThat(dh.getKind()).isEqualTo(KeyAgreement.class);
        assertThat(dh.getChildren().get(KeyLength.class).asString()).isEqualTo(keyLength);
    }

    @ParameterizedTest
    @CsvSource({
        "ECDH-P256,secp256r1",
        "ECDH-P384,secp384r1",
        "ECDH-P521,secp521r1",
        "ECDH-SECP256K1,secp256k1"
    })
    void ecdhKeepsItsCurve(String name, String curve) {
        INode ecdh = parse(name);
        assertThat(ecdh).isInstanceOf(ECDH.class);
        assertThat(ecdh.getChildren().get(EllipticCurve.class).asString()).isEqualTo(curve);
    }

    @Test
    void sm2KeyExchangeIsAKeyAgreement() {
        INode sm2 = parse("SM2");
        assertThat(sm2).isInstanceOf(SM2.class);
        assertThat(sm2.getKind()).isEqualTo(KeyAgreement.class);
    }

    @Test
    void curveAndPostQuantumAlgorithms() {
        assertThat(parse("X25519")).isInstanceOf(X25519.class);
        assertThat(parse("ML-KEM-768")).isInstanceOf(MLKEM.class);
    }

    @Test
    void unknownAndNullNames() {
        assertThat(mapper.parse("XYZ", location)).isEmpty();
        assertThat(mapper.parse(null, location)).isEmpty();
    }
}
