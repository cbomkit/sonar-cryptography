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
package com.ibm.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class CxxAggregatorTest {

    private static final DetectionLocation TEST_LOCATION =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");

    @AfterEach
    void resetSharedState() {
        // CxxAggregator holds its accumulated nodes in static fields shared across every test
        // in the JVM, so each test must leave it clean for the next one.
        CxxAggregator.reset();
    }

    @Test
    void aFreshAggregatorReportsNoDetectedNodes() {
        assertThat(CxxAggregator.getDetectedNodes()).isEmpty();
    }

    @Test
    void addedNodesAreReturnedByGetDetectedNodes() {
        INode rsa = new RSA(TEST_LOCATION);

        CxxAggregator.addNodes(List.of(rsa));

        assertThat(CxxAggregator.getDetectedNodes()).containsExactly(rsa);
    }

    @Test
    void addingNodesAcrossMultipleCallsAccumulatesThem() {
        INode first = new RSA(TEST_LOCATION);
        INode second = new RSA(2048, TEST_LOCATION);

        CxxAggregator.addNodes(List.of(first));
        CxxAggregator.addNodes(List.of(second));

        assertThat(CxxAggregator.getDetectedNodes()).containsExactly(first, second);
    }

    @Test
    void getDetectedNodesIsUnmodifiable() {
        CxxAggregator.addNodes(List.of(new RSA(TEST_LOCATION)));

        List<INode> detected = CxxAggregator.getDetectedNodes();

        assertThat(detected).hasSize(1);
        org.junit.jupiter.api.Assertions.assertThrows(
                UnsupportedOperationException.class, () -> detected.add(new RSA(TEST_LOCATION)));
    }

    @Test
    void resetClearsAccumulatedNodesAndRebuildsLanguageSupport() {
        CxxAggregator.addNodes(List.of(new RSA(TEST_LOCATION)));

        CxxAggregator.reset();

        assertThat(CxxAggregator.getDetectedNodes()).isEmpty();
        assertThat(CxxAggregator.getLanguageSupport()).isNotNull();
    }
}
