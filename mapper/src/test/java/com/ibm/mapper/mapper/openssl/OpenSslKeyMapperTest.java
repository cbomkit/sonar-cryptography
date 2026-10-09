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
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import com.ibm.mapper.model.algorithms.SPHINCSPlus;
import com.ibm.mapper.model.curves.Brainpoolp256r1;
import com.ibm.mapper.model.curves.Secp256r1;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class OpenSslKeyMapperTest {

    private final DetectionLocation location =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");
    private final OpenSslKeyMapper mapper = new OpenSslKeyMapper();

    private INode parse(String name) {
        return mapper.parse(name, location).orElseThrow();
    }

    @Test
    void ecKeyOnANamedCurve() {
        INode ec = parse("EC-P-256");
        assertThat(ec.asString()).isEqualTo("EC-secp256r1");
        assertThat(ec.getChildren().get(EllipticCurve.class)).isInstanceOf(Secp256r1.class);
    }

    @Test
    void rsaAndDsaKeepAnyBitLength() {
        INode rsa = parse("RSA-3000");
        assertThat(rsa).isInstanceOf(RSA.class);
        assertThat(rsa.getChildren().get(KeyLength.class).asString()).isEqualTo("3000");
        INode dsa = parse("DSA-2048");
        assertThat(dsa).isInstanceOf(DSA.class);
        assertThat(dsa.getChildren().get(KeyLength.class).asString()).isEqualTo("2048");
    }

    @Test
    void rsaPssIsNotAnRsaKeyLength() {
        assertThat(parse("RSA-PSS")).isInstanceOf(RSAssaPSS.class);
    }

    @Test
    void dhGroupsKeepTheirPrimeSize() {
        assertThat(parse("DH-3072").getChildren().get(KeyLength.class).asString())
                .isEqualTo("3072");
        assertThat(parse("DH-2048-224")).isInstanceOf(DH.class);
    }

    @Test
    void postQuantumParameterSets() {
        assertThat(parse("SLH-DSA-SHAKE-256F")).isInstanceOf(SPHINCSPlus.class);
    }

    @Test
    void curves() {
        assertThat(mapper.parseCurve("ec-brainpoolP256r1", location))
                .containsInstanceOf(Brainpoolp256r1.class);
        assertThat(mapper.parseCurve("EC-UNKNOWN", location)).isEmpty();
    }

    @Test
    void invalidBitLengthsAndUnknownNames() {
        assertThat(mapper.parse("RSA-0", location)).isEmpty();
        assertThat(mapper.parse("XYZ", location)).isEmpty();
        assertThat(mapper.parse(null, location)).isEmpty();
    }
}
