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
package com.ibm.plugin.bridge;

import com.ibm.plugin.bridge.model.EslintAnalysisResult;
import com.ibm.plugin.bridge.model.EslintFileResult;
import com.ibm.plugin.bridge.model.EslintInputFile;
import com.ibm.plugin.javascript.api.BlockTree;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.fs.InputFile;

/** High-level bridge between SonarQube file inputs and the Node.js ESLint analysis runner. */
public final class ESLintBridge {

    @Nonnull private static final Logger LOG = LoggerFactory.getLogger(ESLintBridge.class);

    @Nonnull private final ESLintExecutor executor;

    public ESLintBridge(@Nonnull ESLintExecutor executor) {
        this.executor = executor;
    }

    @Nonnull
    public static ESLintBridge createDefault() throws IOException {
        return new ESLintBridge(ESLintExecutor.fromClasspathResources());
    }

    @Nonnull
    public Map<InputFile, BlockTree> analyzeFiles(@Nonnull List<InputFile> inputFiles)
            throws IOException {
        List<EslintInputFile> payload = inputFiles.stream().map(this::toInputFile).toList();
        EslintAnalysisResult result = executor.analyze(payload);
        Map<InputFile, BlockTree> trees = new HashMap<>();
        if (result.files == null) {
            return trees;
        }
        for (EslintFileResult fileResult : result.files) {
            InputFile inputFile = findInputFile(inputFiles, fileResult.path);
            if (inputFile == null) {
                LOG.warn("No matching input file for ESLint result path: {}", fileResult.path);
                continue;
            }
            if (fileResult.parseError != null && !fileResult.parseError.isBlank()) {
                LOG.warn("Failed to parse {}: {}", inputFile, fileResult.parseError);
                trees.put(inputFile, new BlockTree(List.of()));
                continue;
            }
            trees.put(inputFile, ESLintResultParser.toBlockTree(fileResult));
        }
        return trees;
    }

    @Nullable private InputFile findInputFile(@Nonnull List<InputFile> inputFiles, @Nullable String path) {
        if (path == null) {
            return null;
        }
        for (InputFile inputFile : inputFiles) {
            if (path.equals(inputFile.uri().getPath()) || path.equals(inputFile.toString())) {
                return inputFile;
            }
        }
        return null;
    }

    @Nonnull
    private EslintInputFile toInputFile(@Nonnull InputFile inputFile) {
        try {
            return new EslintInputFile(inputFile.uri().getPath(), inputFile.contents());
        } catch (IOException e) {
            throw new IllegalStateException("Unable to read " + inputFile, e);
        }
    }
}
