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
package com.ibm.enricher.algorithm;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.enricher.TestBase;
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.MD2;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.PBES1;
import com.ibm.mapper.model.algorithms.RC2;
import com.ibm.mapper.model.algorithms.RC4;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.TripleDES;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class PBES1EnricherTest extends TestBase {

    private static final DetectionLocation LOC =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "Jca");

    static Stream<Arguments> oidTable() {
        return Stream.of(
                // PKCS#5
                Arguments.of(
                        Named.of("MD2+DES", pbes1(new MD2(LOC), new DES(LOC))),
                        "1.2.840.113549.1.5.1"),
                Arguments.of(
                        Named.of("MD5+DES", pbes1(new MD5(LOC), new DES(LOC))),
                        "1.2.840.113549.1.5.3"),
                Arguments.of(
                        Named.of("MD2+RC2", pbes1(new MD2(LOC), new RC2(LOC))),
                        "1.2.840.113549.1.5.4"),
                Arguments.of(
                        Named.of("MD5+RC2", pbes1(new MD5(LOC), new RC2(LOC))),
                        "1.2.840.113549.1.5.6"),
                Arguments.of(
                        Named.of("SHA+DES", pbes1(new SHA(LOC), new DES(LOC))),
                        "1.2.840.113549.1.5.10"),
                Arguments.of(
                        Named.of("SHA+RC2(default)", pbes1(new SHA(LOC), new RC2(LOC))),
                        "1.2.840.113549.1.5.11"),
                // PKCS#12
                Arguments.of(
                        Named.of("SHA+RC4-128", pbes1(new SHA(LOC), new RC4(128, LOC))),
                        "1.2.840.113549.1.12.1.1"),
                Arguments.of(
                        Named.of("SHA+RC4-40", pbes1(new SHA(LOC), new RC4(40, LOC))),
                        "1.2.840.113549.1.12.1.2"),
                Arguments.of(
                        Named.of("SHA+3DES-192", pbes1(new SHA(LOC), new TripleDES(192, LOC))),
                        "1.2.840.113549.1.12.1.3"),
                Arguments.of(
                        Named.of("SHA+3DES-168", pbes1(new SHA(LOC), new TripleDES(168, LOC))),
                        "1.2.840.113549.1.12.1.3"),
                Arguments.of(
                        Named.of("SHA+3DES-128", pbes1(new SHA(LOC), new TripleDES(128, LOC))),
                        "1.2.840.113549.1.12.1.4"),
                Arguments.of(
                        Named.of("SHA+3DES-112", pbes1(new SHA(LOC), new TripleDES(112, LOC))),
                        "1.2.840.113549.1.12.1.4"),
                Arguments.of(
                        Named.of("SHA+RC2-128", pbes1(new SHA(LOC), new RC2(128, LOC))),
                        "1.2.840.113549.1.12.1.5"),
                Arguments.of(
                        Named.of("SHA+RC2-40", pbes1(new SHA(LOC), new RC2(40, LOC))),
                        "1.2.840.113549.1.12.1.6"));
    }

    @ParameterizedTest
    @MethodSource("oidTable")
    void resolvesOid(PBES1 pbes1, String expectedOid) {
        final INode enriched = new PBES1Enricher().enrich(pbes1);

        assertThat(enriched.hasChildOfType(Oid.class)).isPresent();
        assertThat(enriched.hasChildOfType(Oid.class).get().asString()).isEqualTo(expectedOid);
    }

    @ParameterizedTest
    @MethodSource("noOidTable")
    void noOidForUnknownKeyLength(PBES1 pbes1) {
        final INode enriched = new PBES1Enricher().enrich(pbes1);

        assertThat(enriched.hasChildOfType(Oid.class)).isEmpty();
    }

    static Stream<Arguments> noOidTable() {
        return Stream.of(
                // No PKCS#5 OID defined for SHA1+RC4 with key lengths other than 128 or 40
                Arguments.of(Named.of("SHA+RC4-64", pbes1(new SHA(LOC), new RC4(64, LOC)))));
    }

    private static PBES1 pbes1(MessageDigest digest, Cipher cipher) {
        return new PBES1(digest, cipher);
    }
}
