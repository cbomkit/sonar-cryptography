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
package com.ibm.mapper.mapper.openssl;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.curves.Brainpoolp256r1;
import com.ibm.mapper.model.curves.Secp192r1;
import com.ibm.mapper.model.curves.Secp256k1;
import com.ibm.mapper.model.curves.Secp256r1;
import com.ibm.mapper.model.curves.Secp521r1;
import com.ibm.mapper.model.curves.Sect163r2;
import com.ibm.mapper.model.curves.Sect283k1;
import com.ibm.mapper.model.curves.Sect571r1;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class OpenSslCurveMapperTest {

    private final DetectionLocation location =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");
    private final OpenSslCurveMapper mapper = new OpenSslCurveMapper();

    @Test
    void nistSecAndX962NamesOfACurve() {
        assertThat(mapper.parse("P-256", location)).containsInstanceOf(Secp256r1.class);
        assertThat(mapper.parse("secp256r1", location)).containsInstanceOf(Secp256r1.class);
        assertThat(mapper.parse("prime256v1", location)).containsInstanceOf(Secp256r1.class);
        assertThat(mapper.parse("P-521", location)).containsInstanceOf(Secp521r1.class);
        assertThat(mapper.parse("prime192v1", location)).containsInstanceOf(Secp192r1.class);
    }

    @Test
    void koblitzAndBrainpoolCurves() {
        assertThat(mapper.parse("secp256k1", location)).containsInstanceOf(Secp256k1.class);
        assertThat(mapper.parse("brainpoolP256r1", location))
                .containsInstanceOf(Brainpoolp256r1.class);
    }

    @Test
    void binaryCurvesByNistAndSecNames() {
        assertThat(mapper.parse("sect283k1", location)).containsInstanceOf(Sect283k1.class);
        assertThat(mapper.parse("K-283", location)).containsInstanceOf(Sect283k1.class);
        assertThat(mapper.parse("sect163r2", location)).containsInstanceOf(Sect163r2.class);
        assertThat(mapper.parse("B-163", location)).containsInstanceOf(Sect163r2.class);
        assertThat(mapper.parse("B-571", location)).containsInstanceOf(Sect571r1.class);
    }

    @Test
    void unknownNames() {
        assertThat(mapper.parse("P256", location)).isEmpty();
        assertThat(mapper.parse("X25519", location)).isEmpty();
        assertThat(mapper.parse(null, location)).isEmpty();
    }

    /** The named curves of OpenSSL 3 ({@code openssl ecparam -list_curves}). */
    @ParameterizedTest
    @ValueSource(
            strings = {
                "prime192v1",
                "prime192v2",
                "prime192v3",
                "prime239v1",
                "prime239v2",
                "prime239v3",
                "prime256v1",
                "c2pnb163v1",
                "c2pnb163v2",
                "c2pnb163v3",
                "c2pnb176v1",
                "c2tnb191v1",
                "c2tnb191v2",
                "c2tnb191v3",
                "c2pnb208w1",
                "c2tnb239v1",
                "c2tnb239v2",
                "c2tnb239v3",
                "c2pnb272w1",
                "c2pnb304w1",
                "c2tnb359v1",
                "c2pnb368w1",
                "c2tnb431r1",
                "secp112r1",
                "secp112r2",
                "secp128r1",
                "secp128r2",
                "secp160k1",
                "secp160r1",
                "secp160r2",
                "secp192k1",
                "secp224k1",
                "secp224r1",
                "secp256k1",
                "secp384r1",
                "secp521r1",
                "sect113r1",
                "sect113r2",
                "sect131r1",
                "sect131r2",
                "sect163k1",
                "sect163r1",
                "sect163r2",
                "sect193r1",
                "sect193r2",
                "sect233k1",
                "sect233r1",
                "sect239k1",
                "sect283k1",
                "sect283r1",
                "sect409k1",
                "sect409r1",
                "sect571k1",
                "sect571r1",
                "wap-wsg-idm-ecid-wtls1",
                "wap-wsg-idm-ecid-wtls3",
                "wap-wsg-idm-ecid-wtls4",
                "wap-wsg-idm-ecid-wtls5",
                "wap-wsg-idm-ecid-wtls6",
                "wap-wsg-idm-ecid-wtls7",
                "wap-wsg-idm-ecid-wtls8",
                "wap-wsg-idm-ecid-wtls9",
                "wap-wsg-idm-ecid-wtls10",
                "wap-wsg-idm-ecid-wtls11",
                "wap-wsg-idm-ecid-wtls12",
                "Oakley-EC2N-3",
                "Oakley-EC2N-4",
                "brainpoolP160r1",
                "brainpoolP160t1",
                "brainpoolP192r1",
                "brainpoolP192t1",
                "brainpoolP224r1",
                "brainpoolP224t1",
                "brainpoolP256r1",
                "brainpoolP256t1",
                "brainpoolP320r1",
                "brainpoolP320t1",
                "brainpoolP384r1",
                "brainpoolP384t1",
                "brainpoolP512r1",
                "brainpoolP512t1",
                "SM2"
            })
    void everyNamedCurveOfOpenSsl(String name) {
        assertThat(mapper.parse(name, location)).as(name).isPresent();
    }

    @Test
    void aCurveWithoutAModelOfItsOwnIsNamedByItsShortName() {
        assertThat(mapper.parse("PRIME239V1", location))
                .get()
                .extracting(EllipticCurve::asString)
                .isEqualTo("prime239v1");
        assertThat(mapper.parse("wap-wsg-idm-ecid-wtls7", location))
                .get()
                .extracting(EllipticCurve::asString)
                .isEqualTo("wap-wsg-idm-ecid-wtls7");
    }
}
