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
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.CMAC;
import com.ibm.mapper.model.algorithms.GMAC;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class OpenSslMacMapperTest {

    private final DetectionLocation location =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");
    private final OpenSslMacMapper mapper = new OpenSslMacMapper();

    private INode parse(String name) {
        return mapper.parse(name, location).orElseThrow();
    }

    @Test
    void hmacAndCmacWithTheirAlgorithm() {
        assertThat(parse("HMAC-SHA256")).isInstanceOf(HMAC.class);
        assertThat(parse("HMAC-SHA256").asString()).isEqualTo("HMAC-SHA-256");
        assertThat(parse("CMAC-AES-128")).isInstanceOf(CMAC.class);
    }

    @Test
    void gmacWithAKnownCipherIsTheCipherInGmacMode() {
        INode gmac = parse("GMAC-AES-128");
        assertThat(gmac).isInstanceOf(AES.class);
        assertThat(gmac.getKind()).isEqualTo(Mac.class);
        assertThat(gmac.getChildren().get(Mode.class))
                .isInstanceOf(com.ibm.mapper.model.mode.GMAC.class);
        assertThat(gmac.asString()).isEqualTo("AES-128-GMAC");
    }

    @Test
    void gmacWithoutCipher() {
        INode gmac = parse("GMAC");
        assertThat(gmac).isInstanceOf(GMAC.class);
        assertThat(gmac.asString()).isEqualTo("GMAC");
    }

    @Test
    void unknownAndNullNames() {
        assertThat(mapper.parse("XYZ", location)).isEmpty();
        assertThat(mapper.parse(null, location)).isEmpty();
    }
}
