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
import com.ibm.output.IOutputFile;
import com.ibm.output.IOutputFileFactory;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ScannerManagerTest {

    @BeforeEach
    @AfterEach
    void clearAggregators() {
        JavaAggregator.reset();
        PythonAggregator.reset();
        GoAggregator.reset();
        CxxAggregator.reset();
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

    @Test
    void getOutputFileIncludesNodesFromEveryLanguageAggregator() {
        JavaAggregator.addNodes(List.<INode>of(new AES(128, javaLocation())));
        PythonAggregator.addNodes(List.<INode>of(new AES(128, pythonLocation())));
        GoAggregator.addNodes(List.<INode>of(new AES(128, goLocation())));
        CxxAggregator.addNodes(List.<INode>of(new AES(128, cxxLocation())));

        RecordingOutputFileFactory factory = new RecordingOutputFileFactory();
        new ScannerManager(factory).getOutputFile();

        assertThat(factory.recordedNodes).hasSize(4);
    }

    @Test
    void hasResultsIsTrueWhenOnlyCxxAggregatorHasNodes() {
        CxxAggregator.addNodes(List.<INode>of(new AES(128, cxxLocation())));

        assertThat(new ScannerManager(null).hasResults()).isTrue();
    }

    @Test
    void hasResultsIsTrueWhenOnlyPythonAggregatorHasNodes() {
        PythonAggregator.addNodes(List.<INode>of(new AES(128, pythonLocation())));

        assertThat(new ScannerManager(null).hasResults()).isTrue();
    }

    @Test
    void hasResultsIsTrueWhenOnlyGoAggregatorHasNodes() {
        GoAggregator.addNodes(List.<INode>of(new AES(128, goLocation())));

        assertThat(new ScannerManager(null).hasResults()).isTrue();
    }

    private static DetectionLocation javaLocation() {
        return new DetectionLocation("Test.java", 1, 0, List.of("aes"), () -> "test");
    }

    private static DetectionLocation pythonLocation() {
        return new DetectionLocation("test.py", 1, 0, List.of("aes"), () -> "test");
    }

    private static DetectionLocation goLocation() {
        return new DetectionLocation("test.go", 1, 0, List.of("aes"), () -> "test");
    }

    private static DetectionLocation cxxLocation() {
        return new DetectionLocation("test.cc", 1, 0, List.of("aes"), () -> "test");
    }

    /** Records the node list it is asked to format, so the test can inspect it directly. */
    private static final class RecordingOutputFileFactory implements IOutputFileFactory {
        private List<INode> recordedNodes = List.of();

        @Override
        public IOutputFile createOutputFormat(List<INode> nodes) {
            this.recordedNodes = new ArrayList<>(nodes);
            return new IOutputFile() {
                @Override
                public void add(List<INode> nodes) {
                    // not exercised by this test
                }

                @Override
                public void saveTo(File file) {
                    // not exercised by this test
                }
            };
        }
    }
}
