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

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.model.collections.MergeableCollection;
import com.ibm.mapper.model.protocol.TLS;
import java.util.List;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.crypto.ProtocolProperties;
import org.junit.jupiter.api.Test;

/**
 * The assets of a mergeable collection, such as the groups and signature algorithms configured on a
 * TLS context, are each added to the CBOM; held by a protocol, they are the algorithms it uses.
 */
class MergeableCollectionTest extends TestBase {

    @Test
    void assetsOfATopLevelCollection() {
        this.assertsNode(
                () -> new MergeableCollection(algorithms()),
                bom -> {
                    assertThat(bom.getComponents())
                            .extracting(Component::getName)
                            .containsExactlyInAnyOrder("x25519", "ECDH");
                    bom.getComponents().forEach(component -> asserts(component.getEvidence()));
                });
    }

    @Test
    void assetsOfACollectionHeldByAProtocol() {
        this.assertsNode(
                () -> {
                    final TLS tls = new TLS(detectionLocation);
                    tls.put(new MergeableCollection(algorithms()));
                    return tls;
                },
                bom -> {
                    assertThat(bom.getComponents())
                            .extracting(Component::getName)
                            .containsExactlyInAnyOrder("TLS", "x25519", "ECDH");
                    final ProtocolProperties protocolProperties =
                            bom.getComponents().stream()
                                    .filter(component -> component.getName().equals("TLS"))
                                    .findFirst()
                                    .orElseThrow()
                                    .getCryptoProperties()
                                    .getProtocolProperties();
                    assertThat(protocolProperties.getCryptoRefArray()).hasSize(2);
                });
    }

    private List<INode> algorithms() {
        return List.of(new X25519(detectionLocation), new ECDH(detectionLocation));
    }
}
