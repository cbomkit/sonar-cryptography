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

import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.algorithms.DHKEM;
import com.ibm.mapper.model.algorithms.HPKE;
import com.ibm.mapper.model.algorithms.MLKEM;
import com.ibm.mapper.model.algorithms.RSASVE;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class OpenSslKemMapperTest {

    private final DetectionLocation location =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");
    private final OpenSslKemMapper mapper = new OpenSslKemMapper();

    @Test
    void rsaEncapsulationIsRsasve() {
        assertThat(mapper.parse("RSA", location).orElseThrow()).isInstanceOf(RSASVE.class);
    }

    @Test
    void ellipticCurveEncapsulationIsDhkem() {
        INode dhkem = mapper.parse("X25519", location).orElseThrow();
        assertThat(dhkem).isInstanceOf(DHKEM.class);
        assertThat(dhkem.getKind()).isEqualTo(KeyEncapsulationMechanism.class);
        assertThat(dhkem.getChildren().get(KeyAgreement.class).asString()).isEqualTo("x25519");
    }

    @Test
    void otherNamesAreKeyAgreementNames() {
        assertThat(mapper.parse("ML-KEM-512", location).orElseThrow()).isInstanceOf(MLKEM.class);
    }

    @Test
    void hpkeSuite() {
        HPKE hpke = mapper.parseHpkeSuite("P-256,HKDF-SHA256,AES-128-GCM", location).orElseThrow();
        INode dhkem = hpke.getChildren().get(KeyEncapsulationMechanism.class);
        assertThat(dhkem).isInstanceOf(DHKEM.class);
        assertThat(
                        dhkem.getChildren()
                                .get(KeyAgreement.class)
                                .getChildren()
                                .get(EllipticCurve.class)
                                .asString())
                .isEqualTo("secp256r1");
        assertThat(hpke.getChildren().get(KeyDerivationFunction.class).asString())
                .isEqualTo("HKDF-SHA-256");
        assertThat(hpke.getChildren().get(BlockCipher.class)).isNotNull();
    }

    @Test
    void hpkeSuiteWithExportOnlyAeadHasNoCipher() {
        HPKE hpke = mapper.parseHpkeSuite("X25519,HKDF-SHA256,EXPORTONLY", location).orElseThrow();
        assertThat(hpke.hasChildOfType(BlockCipher.class)).isEmpty();
        assertThat(hpke.hasChildOfType(AuthenticatedEncryption.class)).isEmpty();
    }

    @Test
    void malformedSuites() {
        assertThat(mapper.parseHpkeSuite("X25519,HKDF-SHA256", location)).isEmpty();
        assertThat(mapper.parseHpkeSuite("UNKNOWN,HKDF-SHA256,AES-128-GCM", location)).isEmpty();
        assertThat(mapper.parseHpkeSuite(null, location)).isEmpty();
    }
}
