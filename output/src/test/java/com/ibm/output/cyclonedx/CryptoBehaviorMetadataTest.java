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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.output.cyclondx.CBOMOutputFile;
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
        assertThat(property.getName()).isEqualTo("cbomkit:crypto:behavior");
        assertThat(property.getValue())
                .isEqualTo(
                        "security:cryptography:authenticates,"
                                + "security:cryptography:encryptsData,"
                                + "security:cryptography:ensuresConfidentiality,"
                                + "security:cryptography:ensuresIntegrity,"
                                + "security:cryptography:hashesData");
    }

    @Test
    void noMetadataComponentWhenNoBehaviorsDetected() {
        // A lone functionality node is not an Algorithm asset, so the mapper returns no behaviors
        // and getBom() must not create a metadata.component (spec §6).
        final Bom bom = bomOf(List.of(new Encrypt(loc)));
        assertThat(bom.getMetadata().getComponent()).isNull();
    }
}
