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
package com.ibm.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ScannerManagerTest {

    @BeforeEach
    @AfterEach
    void clearAggregators() {
        JavaAggregator.reset();
    }

    @Test
    void heapAttributionReportsZeroPopulationsOnAFreshScanner() {
        HeapAttributionSummary summary = new ScannerManager(null).heapAttribution();
        assertThat(summary.detectedNodes()).isZero();
        assertThat(summary.totalCalls()).isZero();
        assertThat(summary.callStackBuckets()).isZero();
    }

    @Test
    void heapAttributionCountsRetainedDetectedNodes() {
        DetectionLocation location =
                new DetectionLocation("Test.java", 1, 0, List.of("aes"), () -> "test");
        JavaAggregator.addNodes(List.<INode>of(new AES(128, location)));

        HeapAttributionSummary summary = new ScannerManager(null).heapAttribution();
        assertThat(summary.detectedNodes()).isEqualTo(1);
    }
}
