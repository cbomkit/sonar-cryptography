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
import com.ibm.mapper.model.collections.AssetCollection;
import java.util.List;
import org.cyclonedx.model.Component;
import org.junit.jupiter.api.Test;

/**
 * The assets of a collection that is not held by another asset, such as the key exchange groups
 * configured for TLS, are each added to the CBOM.
 */
class AssetCollectionTest extends TestBase {

    @Test
    void assetsOfATopLevelCollection() {
        this.assertsNode(
                () ->
                        new AssetCollection(
                                List.<INode>of(
                                        new X25519(detectionLocation),
                                        new ECDH(detectionLocation))),
                bom -> {
                    assertThat(bom.getComponents())
                            .extracting(Component::getName)
                            .containsExactlyInAnyOrder("x25519", "ECDH");
                    bom.getComponents().forEach(component -> asserts(component.getEvidence()));
                });
    }
}
