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
package com.ibm.enricher.algorithm;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * An RSA key that signs with PSS carries the RSASSA-PSS OID, like the {@link RSAssaPSS} node of an
 * unlinked PSS signature; any other RSA keeps the generic one.
 */
class RSAssaPSSEnricherTest {

    private final DetectionLocation location =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "Test");

    @Test
    void rsaSsaPss() {
        INode enriched = new RSAssaPSSEnricher().enrich(new RSAssaPSS(location));
        assertThat(enriched.hasChildOfType(Oid.class).orElseThrow().asString())
                .isEqualTo("1.2.840.113549.1.1.10");
    }

    @Test
    void rsaKeyWithPssPadding() {
        RSA rsa = new RSA(3072, location);
        rsa.put(new Padding("PSS", location));
        INode enriched = new RSAssaPSSEnricher().enrich(rsa);
        assertThat(enriched.asString()).isEqualTo("RSA-PSS");
        assertThat(enriched.hasChildOfType(Oid.class).orElseThrow().asString())
                .isEqualTo("1.2.840.113549.1.1.10");
    }

    @Test
    void rsaKeyWithoutPssKeepsTheRsaOid() {
        RSA plain = new RSA(3072, location);
        RSA pkcs1 = new RSA(3072, location);
        pkcs1.put(new PKCS1(location));
        for (RSA rsa : List.of(plain, pkcs1)) {
            INode enriched = new RSAssaPSSEnricher().enrich(rsa);
            assertThat(enriched.asString()).isEqualTo("RSA-3072");
            assertThat(enriched.hasChildOfType(Oid.class).orElseThrow().asString())
                    .isEqualTo("1.2.840.113549.1.1.1");
        }
    }
}
