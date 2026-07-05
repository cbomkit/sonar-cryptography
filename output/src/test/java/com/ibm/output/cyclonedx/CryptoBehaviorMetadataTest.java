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
package com.ibm.output.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.ContextualEvidence;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.output.cyclondx.CBOMOutputFile;
import com.ibm.output.cyclondx.behavior.CryptoBehaviorMapper;
import java.util.Collections;
import java.util.List;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Property;
import org.junit.jupiter.api.Test;

class CryptoBehaviorMetadataTest {

    private final IBundle bundle = () -> "Test";
    private final DetectionLocation loc =
            new DetectionLocation("test.java", 1, 1, Collections.emptyList(), bundle);

    private Bom bomOf(List<INode> nodes) {
        final CBOMOutputFile outputFile = new CBOMOutputFile();
        nodes.forEach(node -> outputFile.add(List.of(node)));
        return outputFile.getBom();
    }

    @Test
    void aggregatesBehaviorsOfWholeScanOntoMetadataComponent() {
        final AES aes = new AES(loc);
        aes.put(new Encrypt(loc));
        final Bom bom = bomOf(List.of(aes, new SHA2(256, loc), new HMAC(loc)));

        final Component metaComponent = bom.getMetadata().getComponent();
        assertThat(metaComponent).isNotNull();
        assertThat(metaComponent.getType()).isEqualTo(Component.Type.APPLICATION);

        assertThat(metaComponent.getProperties()).hasSize(1);
        final Property property = metaComponent.getProperties().get(0);
        assertThat(property.getName()).isEqualTo(CryptoBehaviorMapper.BEHAVIOR_PROPERTY_NAME);
        assertThat(property.getValue())
                .isEqualTo(
                        "security:cryptography:encryptsData=high,"
                                + "security:cryptography:ensuresConfidentiality=high,"
                                + "security:cryptography:ensuresIntegrity=high,"
                                + "security:cryptography:hashesData=high");
    }

    @Test
    void authInterfaceUnlocksAuthenticatesAndValidatesToken() {
        final AES aes = new AES(loc);
        aes.put(new Encrypt(loc));
        final Bom bom = bomOf(List.of(aes, new ContextualEvidence("JWT", loc)));

        final Property property = bom.getMetadata().getComponent().getProperties().get(0);
        assertThat(property.getValue())
                .contains("security:cryptography:authenticates=high")
                .contains("security:cryptography:validatesToken=high")
                .contains("security:cryptography:encryptsData=high");
    }

    @Test
    void noMetadataComponentWhenNoBehaviorsDetected() {
        // A lone functionality node is not an Algorithm asset, so the mapper returns no behaviors
        // and getBom() must not create a metadata.component (spec §6).
        final Bom bom = bomOf(List.of(new Encrypt(loc)));
        assertThat(bom.getMetadata().getComponent()).isNull();
    }

    @Test
    void protocolCipherSuiteConstituentsContributeBehaviors() {
        // Regression: algorithms nested inside TLS cipher-suites bypassed the behavior mapper
        // because createProtocolComponent calls createAlgorithmComponent directly, not via add().
        final TLS tls = new TLS(new Version("1.3", loc));
        final CipherSuite cipherSuite = new CipherSuite("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", loc);
        final AES aes = new AES(256, new CBC(loc), loc);
        final AssetCollection assetCollection = new AssetCollection(List.of(aes));
        cipherSuite.put(assetCollection);
        tls.put(new CipherSuiteCollection(List.of(cipherSuite)));

        final Bom bom = bomOf(List.of(tls));

        // AES-256-CBC is a BlockCipher with no explicit Functionality child → fallback:
        // encryptsData, decryptsData, ensuresConfidentiality.
        final Component metaComponent = bom.getMetadata().getComponent();
        assertThat(metaComponent).isNotNull();
        final Property property = metaComponent.getProperties().get(0);
        assertThat(property.getValue()).contains("security:cryptography:decryptsData");
        assertThat(property.getValue()).contains("security:cryptography:encryptsData");
        assertThat(property.getValue()).contains("security:cryptography:ensuresConfidentiality");
    }
}
