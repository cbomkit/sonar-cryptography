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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ibm.plugin.bridge.ESLintBridge;
import com.ibm.plugin.javascript.api.BlockTree;
import com.ibm.plugin.rules.JavaScriptInventoryRule;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.sonar.api.batch.fs.FilePredicate;
import org.sonar.api.batch.fs.FilePredicates;
import org.sonar.api.batch.fs.FileSystem;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.api.batch.sensor.Sensor;
import org.sonar.api.batch.sensor.SensorContext;

class CryptoJavaScriptSensorTest {

    @Test
    void implementsSensorContract() throws Exception {
        assertThat(new CryptoJavaScriptSensor()).isInstanceOf(Sensor.class);
    }

    @Test
    void execute_analyzesMainJavaScriptFiles() throws Exception {
        InputFile inputFile =
                TestInputFileBuilder.create("module", "src/crypto.js")
                        .setLanguage("js")
                        .setType(InputFile.Type.MAIN)
                        .setContents("const crypto = require('crypto'); crypto.createHash('md5');")
                        .build();

        BlockTree blockTree = new BlockTree(List.of());
        TrackingInventoryRule inventoryRule = new TrackingInventoryRule();
        ESLintBridge eslintBridge = mock(ESLintBridge.class);
        when(eslintBridge.analyzeFiles(List.of(inputFile)))
                .thenReturn(Map.of(inputFile, blockTree));

        CryptoJavaScriptSensor sensor =
                new CryptoJavaScriptSensor(List.of(inventoryRule), eslintBridge);
        sensor.execute(createContextWithFiles(List.of(inputFile)));

        assertThat(inventoryRule.analyzedFiles).containsExactly(inputFile);
        verify(eslintBridge).analyzeFiles(List.of(inputFile));
    }

    @Test
    void execute_skipsWhenNoInputFiles() throws Exception {
        TrackingInventoryRule inventoryRule = new TrackingInventoryRule();
        ESLintBridge eslintBridge = mock(ESLintBridge.class);

        CryptoJavaScriptSensor sensor =
                new CryptoJavaScriptSensor(List.of(inventoryRule), eslintBridge);
        sensor.execute(createContextWithFiles(List.of()));

        assertThat(inventoryRule.analyzedFiles).isEmpty();
    }

    private static SensorContext createContextWithFiles(List<InputFile> inputFiles) {
        SensorContext context = mock(SensorContext.class);
        FileSystem fileSystem = mock(FileSystem.class);
        FilePredicates predicates = mock(FilePredicates.class);
        FilePredicate filePredicate = mock(FilePredicate.class);

        when(context.fileSystem()).thenReturn(fileSystem);
        when(context.isCancelled()).thenReturn(false);
        when(fileSystem.predicates()).thenReturn(predicates);
        when(predicates.and(
                        org.mockito.ArgumentMatchers.<FilePredicate>any(),
                        org.mockito.ArgumentMatchers.<FilePredicate>any()))
                .thenReturn(filePredicate);
        when(predicates.hasLanguages(org.mockito.ArgumentMatchers.<String>any()))
                .thenReturn(filePredicate);
        when(predicates.hasType(any())).thenReturn(filePredicate);
        when(fileSystem.inputFiles(filePredicate)).thenReturn(inputFiles);
        return context;
    }

    private static final class TrackingInventoryRule extends JavaScriptInventoryRule {
        private final List<InputFile> analyzedFiles = new ArrayList<>();

        @Override
        public void analyzeBlock(
                com.ibm.plugin.javascript.api.BlockTree blockTree,
                com.ibm.plugin.javascript.language.JavaScriptScanContext scanContext) {
            analyzedFiles.add(scanContext.getInputFile());
            super.analyzeBlock(blockTree, scanContext);
        }
    }
}
