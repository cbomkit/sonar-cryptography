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

import org.junit.jupiter.api.Test;

class HeapAttributionSummaryTest {

    @Test
    void formatContainsAllFourPopulationCounts() {
        HeapAttributionSummary summary = new HeapAttributionSummary(1200, 179000, 630000, 15800);
        String line = summary.format();
        assertThat(line)
                .contains("detectedNodes=1200")
                .contains("detachedCalls=179000")
                .contains("totalCalls=630000")
                .contains("callStackBuckets=15800");
    }

    @Test
    void formatIsStableForZeroPopulations() {
        assertThat(new HeapAttributionSummary(0, 0, 0, 0).format())
                .isEqualTo(
                        "[heap-attribution] detectedNodes=0 detachedCalls=0 "
                                + "totalCalls=0 callStackBuckets=0");
    }
}
