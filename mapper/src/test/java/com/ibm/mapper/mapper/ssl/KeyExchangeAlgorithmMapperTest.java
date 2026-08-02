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

import com.ibm.mapper.mapper.ssl.json.JsonCipherSuite;
import com.ibm.mapper.mapper.ssl.json.JsonCipherSuites;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class KeyExchangeAlgorithmMapperTest {

    @Test
    void test() {
        final DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        final KeyExchangeAlgorithmMapper mapper = new KeyExchangeAlgorithmMapper();
        final Collection<String> kexCollection =
                JsonCipherSuites.CIPHER_SUITES.values().stream()
                        .map(JsonCipherSuite::getKexAlgorithm)
                        .filter(Optional::isPresent)
                        .map(Optional::get)
                        .collect(Collectors.toSet());

        for (String kex : kexCollection) {
            if (Objects.equals(kex, "NULL")) {
                continue;
            }

            try {
                assertThat(mapper.parse(kex, testDetectionLocation)).isPresent();
            } catch (AssertionError e) {
                System.out.println("Can't map '" + kex + "'");
                throw e;
            }
        }
    }
}
