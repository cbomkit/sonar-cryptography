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

import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Identifier;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.ascon.AsconAead128;
import com.ibm.mapper.model.algorithms.ascon.AsconHash;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.mapper.utils.Utils;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class CipherSuiteMapperTest {

    @Test
    void test1() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        final CipherSuiteMapper mapper = new CipherSuiteMapper();
        final Optional<? extends INode> node =
                mapper.parse("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", testDetectionLocation);
        assertThat(node).isPresent();
        assertThat(node.get().is(CipherSuite.class)).isTrue();
        final CipherSuite cipherSuite = (CipherSuite) node.get();
        Utils.printNodeTree("tree", List.of(cipherSuite));

        assertThat(cipherSuite.getAssetCollection()).isPresent();
        assertThat(cipherSuite.getIdentifierCollection()).isPresent();

        final List<INode> assetCollection = cipherSuite.getAssetCollection().get().getCollection();
        final List<Identifier> identifierCollection =
                cipherSuite.getIdentifierCollection().get().getCollection();
        assertThat(assetCollection).isNotEmpty();
        assertThat(identifierCollection).isNotEmpty();

        assertThat(identifierCollection.stream().map(Identifier::asString))
                .contains("0x00", "0x6A");

        assertThat(assetCollection)
                .contains(
                        new AES(testDetectionLocation),
                        new DSA(new SHA2(256, testDetectionLocation)),
                        new DH(KeyAgreement.class, testDetectionLocation));
    }

    @Test
    void asconAeadSuite() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        final CipherSuiteMapper mapper = new CipherSuiteMapper();
        final Optional<? extends INode> node =
                mapper.parse("TLS_ASCONAEAD128_SHA256", testDetectionLocation);
        assertThat(node).isPresent();
        assertThat(node.get().is(CipherSuite.class)).isTrue();
        final CipherSuite cipherSuite = (CipherSuite) node.get();

        assertThat(cipherSuite.getIdentifierCollection()).isPresent();
        assertThat(
                        cipherSuite.getIdentifierCollection().get().getCollection().stream()
                                .map(Identifier::asString))
                .contains("0x00", "0x6F");

        assertThat(cipherSuite.getAssetCollection()).isPresent();
        assertThat(cipherSuite.getAssetCollection().get().getCollection())
                .contains(
                        new AsconAead128(testDetectionLocation),
                        new SHA2(256, testDetectionLocation));
    }

    @Test
    void asconHashSuite() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        final CipherSuiteMapper mapper = new CipherSuiteMapper();
        final Optional<? extends INode> node =
                mapper.parse("TLS_AES_128_GCM_ASCONHASH256", testDetectionLocation);
        assertThat(node).isPresent();
        assertThat(node.get().is(CipherSuite.class)).isTrue();
        final CipherSuite cipherSuite = (CipherSuite) node.get();

        assertThat(cipherSuite.getIdentifierCollection()).isPresent();
        assertThat(
                        cipherSuite.getIdentifierCollection().get().getCollection().stream()
                                .map(Identifier::asString))
                .contains("0x00", "0x70");

        assertThat(cipherSuite.getAssetCollection()).isPresent();
        assertThat(cipherSuite.getAssetCollection().get().getCollection())
                .contains(
                        new AES(128, new GCM(testDetectionLocation), testDetectionLocation),
                        new AsconHash(testDetectionLocation));
    }

    @Test
    void findingTest() {
        assertThat(CipherSuiteMapper.findCipherSuite("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"))
                .isPresent();
        assertThat(CipherSuiteMapper.findCipherSuite("TLS_DHE_DSS_AES_256_CBC_SHA256")).isPresent();
        assertThat(CipherSuiteMapper.findCipherSuite("DHE-DSS-AES256-SHA256")).isPresent();
        assertThat(CipherSuiteMapper.findCipherSuite("TLS_ASCONAEAD128_SHA256")).isPresent();
        assertThat(CipherSuiteMapper.findCipherSuite("TLS_AES_128_GCM_ASCONHASH256")).isPresent();
        assertThat(CipherSuiteMapper.findCipherSuite("TLS_AES_128_CCM_ASCONHASH256")).isPresent();
    }
}
