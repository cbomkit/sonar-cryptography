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
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.output.ILanguageModule;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ScannerManagerTest {

    private static final DetectionLocation LOCATION =
            new DetectionLocation("Test.java", 1, 0, List.of("aes"), () -> "test");

    @BeforeEach
    @AfterEach
    void clearAggregators() {
        JavaAggregator.reset();
    }

    @Test
    void aggregatesTheNodesOfAvailableModulesOnly() {
        FakeModule available = new FakeModule(true, new AES(128, LOCATION));
        FakeModule unavailable = new FakeModule(false, new AES(256, LOCATION));
        ScannerManager manager = new ScannerManager(null, List.of(available, unavailable));

        assertThat(manager.hasResults()).isTrue();
        assertThat(available.detectedNodesCalls).isPositive();
        assertThat(unavailable.detectedNodesCalls).isZero();
    }

    @Test
    void resetsAvailableModulesOnly() {
        FakeModule available = new FakeModule(true, new AES(128, LOCATION));
        FakeModule unavailable = new FakeModule(false, new AES(256, LOCATION));
        ScannerManager manager = new ScannerManager(null, List.of(available, unavailable));

        manager.reset();

        assertThat(available.resetCalls).isEqualTo(1);
        assertThat(unavailable.resetCalls).isZero();
        assertThat(manager.hasResults()).isFalse();
    }

    @Test
    void hasNoResultsWithoutModules() {
        assertThat(new ScannerManager(null, List.of()).hasResults()).isFalse();
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
        JavaAggregator.addNodes(List.<INode>of(new AES(128, LOCATION)));

        HeapAttributionSummary summary = new ScannerManager(null).heapAttribution();
        assertThat(summary.detectedNodes()).isEqualTo(1);
    }

    private static final class FakeModule implements ILanguageModule {
        private final boolean available;
        private final List<INode> nodes = new ArrayList<>();
        private int detectedNodesCalls;
        private int resetCalls;

        FakeModule(boolean available, @Nonnull INode node) {
            this.available = available;
            this.nodes.add(node);
        }

        @Nonnull
        @Override
        public String name() {
            return "Fake";
        }

        @Override
        public int order() {
            return 0;
        }

        @Override
        public boolean isAvailable() {
            return available;
        }

        @Nonnull
        @Override
        public List<Object> serverExtensions() {
            return List.of();
        }

        @Nonnull
        @Override
        public List<Object> scannerExtensions() {
            return List.of();
        }

        @Nonnull
        @Override
        public List<INode> detectedNodes() {
            detectedNodesCalls++;
            return List.copyOf(nodes);
        }

        @Override
        public void reset() {
            resetCalls++;
            nodes.clear();
        }
    }
}
