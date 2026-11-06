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

import com.ibm.plugin.javascript.antlr.TypeScriptParser;
import com.ibm.plugin.javascript.language.JavaScriptCheck;
import com.ibm.plugin.javascript.language.JavaScriptParsing;
import com.ibm.plugin.javascript.language.JavaScriptScanContext;
import com.ibm.plugin.javascript.language.JavaScriptTreeConverter;
import com.ibm.plugin.javascript.tree.JavaScriptBlockTree;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.api.batch.sensor.internal.SensorContextTester;

/**
 * ANTLR-based verifier for JavaScript/TypeScript detection rule tests.
 *
 * <p>Parses a {@code .js}/{@code .ts} file with the ANTLR4 TypeScript grammar, converts it to
 * blocks and runs the given {@link JavaScriptCheck} against each. Usage: {@code
 * JavaScriptVerifier.verify("rules/detection/MyTestFile.ts", this);} with the path relative to
 * {@code src/test/files/}.
 */
public final class JavaScriptVerifier {

    private static final String TEST_FILES_ROOT = "src/test/files/";

    private JavaScriptVerifier() {
        // utility
    }

    public static void verify(@Nonnull String relativeTestFilePath, @Nonnull JavaScriptCheck check)
            throws IOException {
        Path filePath = Paths.get(TEST_FILES_ROOT + relativeTestFilePath);
        String content = Files.readString(filePath, StandardCharsets.UTF_8);

        JavaScriptParsing.Result parsed = JavaScriptParsing.parse(content, filePath.toString());
        if (parsed.syntaxErrors() != 0) {
            throw new IllegalStateException(
                    "Test fixture "
                            + filePath
                            + " has "
                            + parsed.syntaxErrors()
                            + " syntax error(s)");
        }
        TypeScriptParser.ProgramContext tree = parsed.tree();

        List<JavaScriptBlockTree> blocks = new JavaScriptTreeConverter().extractBlocks(tree);

        SensorContextTester sensorContext =
                SensorContextTester.create(Paths.get(".").toAbsolutePath().normalize());
        String language = relativeTestFilePath.endsWith(".ts") ? "ts" : "js";
        InputFile inputFile =
                TestInputFileBuilder.create("test-module", filePath.toString())
                        .setContents(content)
                        .setCharset(StandardCharsets.UTF_8)
                        .setLanguage(language)
                        .setType(InputFile.Type.MAIN)
                        .build();
        sensorContext.fileSystem().add(inputFile);

        JavaScriptScanContext scanContext =
                new JavaScriptScanContext(sensorContext, inputFile, "sonar-js-crypto");
        for (JavaScriptBlockTree block : blocks) {
            check.scan(scanContext, block);
        }
    }
}
