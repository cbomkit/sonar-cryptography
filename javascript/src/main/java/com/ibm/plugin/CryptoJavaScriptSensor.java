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

import com.ibm.plugin.bridge.ESLintBridge;
import com.ibm.plugin.javascript.api.BlockTree;
import com.ibm.plugin.javascript.language.JavaScriptScanContext;
import com.ibm.plugin.rules.JavaScriptInventoryRule;
import com.ibm.plugin.rules.JavaScriptNoMD5UseRule;
import com.ibm.plugin.rules.detection.JavaScriptBaseDetectionRule;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.StreamSupport;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.fs.FileSystem;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.sensor.Sensor;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.SensorDescriptor;

/**
 * Sensor for executing cryptography detection rules on JavaScript/TypeScript source files via the
 * ESLint bridge.
 */
public class CryptoJavaScriptSensor implements Sensor {

    private static final Logger LOG = LoggerFactory.getLogger(CryptoJavaScriptSensor.class);

    private static final List<String> SUPPORTED_LANGUAGES = List.of("js", "jsx", "ts", "tsx");

    @Nonnull private final List<JavaScriptBaseDetectionRule> detectionRules;
    @Nonnull private final ESLintBridge eslintBridge;

    public CryptoJavaScriptSensor() throws IOException {
        this(
                List.of(new JavaScriptInventoryRule(), new JavaScriptNoMD5UseRule()),
                ESLintBridge.createDefault());
    }

    CryptoJavaScriptSensor(
            @Nonnull List<JavaScriptBaseDetectionRule> detectionRules,
            @Nonnull ESLintBridge eslintBridge) {
        this.detectionRules = List.copyOf(detectionRules);
        this.eslintBridge = eslintBridge;
    }

    @Override
    public void describe(@Nonnull SensorDescriptor descriptor) {
        descriptor
                .name("Cryptography for JavaScript")
                .onlyOnLanguages(SUPPORTED_LANGUAGES.toArray(String[]::new));
    }

    @Override
    public void execute(@Nonnull SensorContext context) {
        FileSystem fileSystem = context.fileSystem();
        List<InputFile> inputFiles =
                StreamSupport.stream(
                                fileSystem
                                        .inputFiles(
                                                fileSystem
                                                        .predicates()
                                                        .and(
                                                                fileSystem
                                                                        .predicates()
                                                                        .hasLanguages(
                                                                                SUPPORTED_LANGUAGES
                                                                                        .toArray(
                                                                                                new String
                                                                                                        [0])),
                                                                fileSystem
                                                                        .predicates()
                                                                        .hasType(
                                                                                InputFile.Type
                                                                                        .MAIN)))
                                        .spliterator(),
                                false)
                        .toList();

        if (inputFiles.isEmpty()) {
            return;
        }

        try {
            Map<InputFile, BlockTree> trees = eslintBridge.analyzeFiles(inputFiles);
            for (Map.Entry<InputFile, BlockTree> entry : trees.entrySet()) {
                if (context.isCancelled()) {
                    return;
                }
                JavaScriptScanContext scanContext =
                        new JavaScriptScanContext(
                                entry.getKey(),
                                new JavaScriptScanContext.SensorIssueReporter(context));
                for (JavaScriptBaseDetectionRule rule : detectionRules) {
                    rule.analyzeBlock(entry.getValue(), scanContext);
                }
            }
        } catch (IOException e) {
            LOG.warn("Unable to analyze JavaScript files with ESLint bridge.", e);
        }
    }
}
