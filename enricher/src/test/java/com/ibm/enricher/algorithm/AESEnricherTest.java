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
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.mode.CFB;
import com.ibm.mapper.model.mode.ECB;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.model.mode.OFB;
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class AESEnricherTest extends TestBase {

    @Test
    void copiedModeBranchesAreEnrichedIndependently() {
        DetectionLocation location =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");
        AES cbc = new AES(128, new CBC(location), location);
        INode ecb = cbc.deepCopy();
        assertThat(ecb).isExactlyInstanceOf(AES.class);
        ecb.put(new ECB(location));

        AESEnricher enricher = new AESEnricher();
        INode enrichedCbc = enricher.enrich(cbc);
        INode enrichedEcb = enricher.enrich(ecb);

        assertThat(enrichedCbc.asString()).isEqualTo("AES-128-CBC");
        assertThat(enrichedEcb.asString()).isEqualTo("AES-128-ECB");
        assertThat(enrichedCbc.hasChildOfType(Oid.class).orElseThrow().asString())
                .isEqualTo("2.16.840.1.101.3.4.1.2");
        assertThat(enrichedEcb.hasChildOfType(Oid.class).orElseThrow().asString())
                .isEqualTo("2.16.840.1.101.3.4.1.1");
    }

    @Test
    void oid() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");
        final AES aes = new AES(256, new ECB(testDetectionLocation), testDetectionLocation);
        this.logBefore(aes);

        final AESEnricher aesEnricher = new AESEnricher();
        final INode enriched = aesEnricher.enrich(aes);
        this.logAfter(enriched);

        assertThat(enriched.is(BlockCipher.class)).isTrue();
        assertThat(enriched).isInstanceOf(AES.class);
        final AES enrichedAES = (AES) enriched;
        assertThat(enrichedAES.hasChildOfType(Oid.class)).isPresent();
        assertThat(enrichedAES.hasChildOfType(Oid.class).get().asString())
                .isEqualTo("2.16.840.1.101.3.4.1.41");
    }

    @Test
    void ae() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");
        final AES aes =
                new AES(
                        128,
                        new GCM(testDetectionLocation),
                        new PKCS1(testDetectionLocation),
                        testDetectionLocation);
        this.logBefore(aes);

        final AESEnricher aesEnricher = new AESEnricher();
        final INode enriched = aesEnricher.enrich(aes);
        this.logAfter(enriched);

        assertThat(enriched.is(AuthenticatedEncryption.class)).isTrue();
        assertThat(enriched).isInstanceOf(AES.class);
        final AES enrichedAES = (AES) enriched;
        assertThat(enrichedAES.hasChildOfType(Oid.class)).isPresent();
        assertThat(enrichedAES.hasChildOfType(Oid.class).get().asString())
                .isEqualTo("2.16.840.1.101.3.4.1.6");
    }

    @Test
    void recastAesDoesNotShareChildrenWithOriginal() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");
        final AES aes = new AES(128, new GCM(testDetectionLocation), testDetectionLocation);

        final AESEnricher aesEnricher = new AESEnricher();
        final INode enriched = aesEnricher.enrich(aes);

        assertThat(enriched).isInstanceOf(AES.class);
        final AES enrichedAES = (AES) enriched;
        enrichedAES.removeChildOfType(Oid.class);

        assertThat(enrichedAES.hasChildOfType(Oid.class)).isEmpty();
        assertThat(aes.hasChildOfType(Oid.class)).isPresent();
        assertThat(aes.hasChildOfType(Oid.class).get().asString())
                .isEqualTo("2.16.840.1.101.3.4.1.6");
    }

    @Test
    void defaultKeyLengthForJca() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "Jca");
        final AES aes = new AES(testDetectionLocation);
        this.logBefore(aes);

        final AESEnricher aesEnricher = new AESEnricher();
        final INode enriched = aesEnricher.enrich(aes);
        this.logAfter(enriched);

        assertThat(enriched).isInstanceOf(AES.class);
        final AES enrichedAES = (AES) enriched;
        assertThat(enrichedAES.getKeyLength()).isPresent();
        assertThat(enrichedAES.getKeyLength().get().asString()).isEqualTo("128");
    }

    @Test
    void cfbAndOfbOidsOnlyForFullBlockFeedback() {
        DetectionLocation location =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");
        final AESEnricher aesEnricher = new AESEnricher();

        // the NIST OIDs for AES in CFB and OFB mode are for a 128-bit feedback
        assertThat(oidOf(aesEnricher.enrich(new AES(128, new CFB(location), location))))
                .isEqualTo("2.16.840.1.101.3.4.1.4");
        assertThat(oidOf(aesEnricher.enrich(new AES(256, new CFB(128, location), location))))
                .isEqualTo("2.16.840.1.101.3.4.1.44");
        assertThat(oidOf(aesEnricher.enrich(new AES(192, new OFB(location), location))))
                .isEqualTo("2.16.840.1.101.3.4.1.23");
        // CFB1 and CFB8 have no OID of their own, whether the width is in the name or given as the
        // block size of the mode
        assertThat(oidOf(aesEnricher.enrich(new AES(128, new CFB(8, location), location))))
                .isEqualTo("2.16.840.1.101.3.4.1");
        assertThat(oidOf(aesEnricher.enrich(new AES(256, new CFB(1, location), location))))
                .isEqualTo("2.16.840.1.101.3.4.1.4");
        final CFB cfbWithBlockSize = new CFB(location);
        cfbWithBlockSize.put(new BlockSize(8, location));
        assertThat(oidOf(aesEnricher.enrich(new AES(128, cfbWithBlockSize, location))))
                .isEqualTo("2.16.840.1.101.3.4.1");
    }

    private static String oidOf(INode node) {
        return node.hasChildOfType(Oid.class).map(INode::asString).orElseThrow();
    }
}
