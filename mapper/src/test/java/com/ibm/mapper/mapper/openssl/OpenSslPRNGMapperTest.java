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

import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.algorithms.CTRDRBG;
import com.ibm.mapper.model.algorithms.HMACDRBG;
import com.ibm.mapper.model.algorithms.HashDRBG;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class OpenSslPRNGMapperTest {

    private final DetectionLocation location =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");
    private final OpenSslPRNGMapper mapper = new OpenSslPRNGMapper();

    @Test
    void drbgs() {
        assertThat(mapper.parse("CTR-DRBG", location).orElseThrow()).isInstanceOf(CTRDRBG.class);
        assertThat(mapper.parse("hash-drbg", location).orElseThrow()).isInstanceOf(HashDRBG.class);
        assertThat(mapper.parse("HMAC-DRBG", location).orElseThrow()).isInstanceOf(HMACDRBG.class);
    }

    @Test
    void entropySources() {
        assertThat(mapper.parse("SEED-SRC", location).orElseThrow().getKind())
                .isEqualTo(PseudorandomNumberGenerator.class);
        assertThat(mapper.parse("RAND", location).orElseThrow().asString()).isEqualTo("RAND");
    }

    @Test
    void seedingOperationsAndUnknownNames() {
        assertThat(mapper.parse("RAND-SEED", location)).isEmpty();
        assertThat(mapper.parse("XYZ", location)).isEmpty();
        assertThat(mapper.parse(null, location)).isEmpty();
    }
}
