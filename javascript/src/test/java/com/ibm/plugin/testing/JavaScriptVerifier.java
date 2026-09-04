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
package com.ibm.plugin.testing;

import com.ibm.plugin.bridge.ESLintBridge;
import com.ibm.plugin.bridge.ESLintExecutor;
import com.ibm.plugin.javascript.api.BlockTree;
import com.ibm.plugin.javascript.language.JavaScriptScanContext;
import com.ibm.plugin.rules.detection.JavaScriptBaseDetectionRule;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;

/** Test harness that runs the ESLint bridge and detection rules against fixture files. */
public final class JavaScriptVerifier {

    private static final Path BASE_DIR = Paths.get("src", "test", "files");

    private JavaScriptVerifier() {
        // utility
    }

    public static void verify(
            @Nonnull String relativePath, @Nonnull JavaScriptBaseDetectionRule rule)
            throws IOException {
        Path path = BASE_DIR.resolve(relativePath);
        String content = Files.readString(path);
        String filename = path.getFileName().toString();

        var inputFile =
                TestInputFileBuilder.create("test-module", filename)
                        .setLanguage(inferLanguage(filename))
                        .setType(org.sonar.api.batch.fs.InputFile.Type.MAIN)
                        .setContents(content)
                        .build();

        ESLintBridge bridge = new ESLintBridge(ESLintExecutor.fromClasspathResources());
        BlockTree blockTree = bridge.analyzeFiles(List.of(inputFile)).get(inputFile);
        if (blockTree == null) {
            throw new IllegalStateException("ESLint bridge returned no tree for " + relativePath);
        }

        JavaScriptScanContext scanContext =
                new JavaScriptScanContext(
                        inputFile,
                        (file, line, column, message) -> {
                            // test noop reporter
                        });
        rule.analyzeBlock(blockTree, scanContext);
    }

    @Nonnull
    private static String inferLanguage(@Nonnull String filename) {
        if (filename.endsWith(".tsx")) {
            return "tsx";
        }
        if (filename.endsWith(".ts")) {
            return "ts";
        }
        if (filename.endsWith(".jsx")) {
            return "jsx";
        }
        return "js";
    }
}
