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

import com.ibm.mapper.model.curves.Brainpoolp256r1;
import com.ibm.mapper.model.curves.Secp192r1;
import com.ibm.mapper.model.curves.Secp256k1;
import com.ibm.mapper.model.curves.Secp256r1;
import com.ibm.mapper.model.curves.Secp521r1;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class OpenSslCurveMapperTest {

    private final DetectionLocation location =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");
    private final OpenSslCurveMapper mapper = new OpenSslCurveMapper();

    @Test
    void nistSecAndX962NamesOfACurve() {
        assertThat(mapper.parse("P-256", location)).containsInstanceOf(Secp256r1.class);
        assertThat(mapper.parse("secp256r1", location)).containsInstanceOf(Secp256r1.class);
        assertThat(mapper.parse("prime256v1", location)).containsInstanceOf(Secp256r1.class);
        assertThat(mapper.parse("P521", location)).containsInstanceOf(Secp521r1.class);
        assertThat(mapper.parse("prime192v1", location)).containsInstanceOf(Secp192r1.class);
    }

    @Test
    void koblitzAndBrainpoolCurves() {
        assertThat(mapper.parse("secp256k1", location)).containsInstanceOf(Secp256k1.class);
        assertThat(mapper.parse("brainpoolP256r1", location))
                .containsInstanceOf(Brainpoolp256r1.class);
    }

    @Test
    void unknownNames() {
        assertThat(mapper.parse("X25519", location)).isEmpty();
        assertThat(mapper.parse(null, location)).isEmpty();
    }
}
