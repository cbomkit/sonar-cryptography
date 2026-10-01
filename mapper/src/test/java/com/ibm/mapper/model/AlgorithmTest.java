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
package com.ibm.mapper.model;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.ascon.Ascon128;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.mode.ECB;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class AlgorithmTest {

    private static final DetectionLocation LOCATION =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

    @Test
    void deepCopyKeepsAesTypeAndSeparatesModeBranches() {
        AES cbc = new AES(128, new CBC(LOCATION), LOCATION);

        INode copied = cbc.deepCopy();
        assertThat(copied).isExactlyInstanceOf(AES.class);
        AES ecb = (AES) copied;
        ecb.put(new ECB(LOCATION));

        assertThat(cbc.asString()).isEqualTo("AES-128-CBC");
        assertThat(ecb.asString()).isEqualTo("AES-128-ECB");
        assertThat(ecb.getChildren()).isNotSameAs(cbc.getChildren());
        assertThat(ecb.hasChildOfType(KeyLength.class).orElseThrow())
                .isNotSameAs(cbc.hasChildOfType(KeyLength.class).orElseThrow());

        ecb.put(new KeyLength(256, LOCATION));
        assertThat(cbc.asString()).isEqualTo("AES-128-CBC");
        assertThat(ecb.asString()).isEqualTo("AES-256-ECB");
    }

    @Test
    void deepCopyKeepsIndirectAndSpecializedTypes() {
        assertThat(new Ascon128(LOCATION).deepCopy()).isExactlyInstanceOf(Ascon128.class);
        assertThat(new EllipticCurveAlgorithm(LOCATION).deepCopy())
                .isExactlyInstanceOf(EllipticCurveAlgorithm.class);

        RSA rsa = new RSA(2048, LOCATION);
        INode copy = rsa.deepCopy();
        assertThat(copy).isExactlyInstanceOf(RSA.class);
        assertThat(copy.hasChildOfType(KeyLength.class).orElseThrow())
                .isNotSameAs(rsa.hasChildOfType(KeyLength.class).orElseThrow());
    }

    @Test
    void deepCopyKeepsMetadata() {
        Algorithm original = new Algorithm("AES", BlockCipher.class, LOCATION, NodeOrigin.DEFAULT);

        Algorithm copy = (Algorithm) original.deepCopy();

        assertThat(copy.getName()).isEqualTo(original.getName());
        assertThat(copy.getKind()).isEqualTo(original.getKind());
        assertThat(copy.getDetectionContext()).isSameAs(original.getDetectionContext());
        assertThat(copy.getOrigin()).isEqualTo(NodeOrigin.DEFAULT);
    }

    @Test
    void recastConstructor_shouldCopyChildrenMap() {
        DetectionLocation detectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        // Create an original algorithm with a child
        Algorithm original = new Algorithm("AES", BlockCipher.class, detectionLocation);
        Algorithm child = new Algorithm("GCM", BlockCipher.class, detectionLocation);
        original.put(child);

        // Recast the algorithm
        Algorithm recast = new Algorithm(original, AuthenticatedEncryption.class);

        // The children maps must not be the same instance
        assertThat(recast.getChildren()).isNotSameAs(original.getChildren());

        // The children maps must have equal content
        assertThat(recast.getChildren()).isEqualTo(original.getChildren());

        // Mutating the recast's children must not affect the original
        recast.getChildren().clear();
        assertThat(original.getChildren()).isNotEmpty();
        assertThat(original.hasChildOfType(BlockCipher.class)).isPresent();
    }
}
