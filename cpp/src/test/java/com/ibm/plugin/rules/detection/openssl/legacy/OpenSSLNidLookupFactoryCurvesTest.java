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
package com.ibm.plugin.rules.detection.openssl.legacy;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.mapper.openssl.OpenSslCurveMapper;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The curve NIDs of {@link OpenSSLNidLookupFactory} cover every named curve of OpenSSL, by their
 * numbers and their names, and each curve they name is mapped.
 */
class OpenSSLNidLookupFactoryCurvesTest {

    private final DetectionLocation location =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");

    @Test
    void theNidNamesAndNumbersNameEveryNamedCurve() {
        final List<String> curves =
                OpenSslCurveMapper.NAMED_CURVES.stream().map(curve -> "EC-" + curve).toList();
        assertThat(OpenSSLNidLookupFactory.CURVE_BY_NAME.values())
                .containsExactlyInAnyOrderElementsOf(curves);
        assertThat(OpenSSLNidLookupFactory.CURVE_BY_CODE.values())
                .containsExactlyInAnyOrderElementsOf(curves);
    }

    @Test
    void theCurvesNamedByNidsAreMapped() {
        OpenSSLNidLookupFactory.CURVE_BY_CODE
                .values()
                .forEach(
                        curve ->
                                assertThat(
                                                new OpenSslCurveMapper()
                                                        .parse(curve.substring(3), location))
                                        .as(curve)
                                        .isPresent());
    }

    @Test
    void aCurveByNidNameAndNumber() {
        assertThat(OpenSSLNidLookupFactory.CURVE_BY_NAME.get("NID_X9_62_prime239v1"))
                .isEqualTo("EC-prime239v1");
        assertThat(OpenSSLNidLookupFactory.CURVE_BY_CODE.get(412)).isEqualTo("EC-prime239v1");
    }
}
