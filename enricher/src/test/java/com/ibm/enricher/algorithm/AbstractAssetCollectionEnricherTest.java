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

import com.ibm.enricher.Enricher;
import com.ibm.enricher.TestBase;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The assets held by a collection are enriched like any other asset. */
class AbstractAssetCollectionEnricherTest extends TestBase {

    private final DetectionLocation location =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

    @Test
    void assetOfATopLevelCollection() {
        final AssetCollection collection =
                new AssetCollection(List.of(new AES(128, new GCM(location), location)));

        final INode enriched = Enricher.enrich(List.of(collection)).iterator().next();

        assertThat(enriched).isInstanceOf(AssetCollection.class);
        assertAuthenticatedAesGcm(((AssetCollection) enriched).getCollection().get(0));
    }

    @Test
    void assetOfACipherSuite() {
        final TLS tls = new TLS(location);
        tls.put(
                new CipherSuiteCollection(
                        List.of(
                                new CipherSuite(
                                        "TLS_AES_128_GCM_SHA256",
                                        new AssetCollection(
                                                List.of(new AES(128, new GCM(location), location))),
                                        location))));

        final INode enriched = Enricher.enrich(List.of(tls)).iterator().next();

        final CipherSuite suite =
                ((CipherSuiteCollection) enriched.getChildren().get(CipherSuiteCollection.class))
                        .getCollection()
                        .get(0);
        assertAuthenticatedAesGcm(suite.getAssetCollection().orElseThrow().getCollection().get(0));
    }

    private static void assertAuthenticatedAesGcm(INode node) {
        assertThat(node).isInstanceOf(AES.class);
        assertThat(node.getKind()).isEqualTo(AuthenticatedEncryption.class);
        assertThat(node.hasChildOfType(Oid.class))
                .map(INode::asString)
                .contains("2.16.840.1.101.3.4.1.6");
    }
}
