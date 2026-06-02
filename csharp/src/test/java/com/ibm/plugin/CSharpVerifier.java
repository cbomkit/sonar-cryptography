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

import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpTreeConverter;
import com.ibm.engine.language.csharp.antlr.CSharpLexer;
import com.ibm.engine.language.csharp.antlr.CSharpParser;
import com.ibm.engine.language.csharp.tree.CSharpBlockTree;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import javax.annotation.Nonnull;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.api.batch.sensor.internal.SensorContextTester;

/**
 * ANTLR-based verifier for C# detection rule tests.
 *
 * <p>Parses a {@code .cs} test file using the ANTLR4 C# grammar, extracts all method bodies, and
 * runs the given {@link CSharpCheck} against each block. Findings are observed directly via the
 * check's internal observer subscription — no native SonarQube binary required.
 *
 * <p>Usage: {@code CSharpVerifier.verify("rules/detection/dotnet/MyTestFile.cs", this);} where the
 * path is relative to {@code src/test/files/}.
 */
public final class CSharpVerifier {

    private static final String TEST_FILES_ROOT = "src/test/files/";

    private CSharpVerifier() {
        // utility
    }

    /**
     * Parses the given test file and runs the check against all discovered method bodies.
     *
     * @param relativeTestFilePath path to the .cs file relative to {@code src/test/files/}
     * @param check the check instance to run (typically a {@code TestBase} subclass)
     */
    public static void verify(@Nonnull String relativeTestFilePath, @Nonnull CSharpCheck check)
            throws IOException {
        Path filePath = Paths.get(TEST_FILES_ROOT + relativeTestFilePath);
        String content = Files.readString(filePath, StandardCharsets.UTF_8);

        CSharpLexer lexer = new CSharpLexer(CharStreams.fromString(content, filePath.toString()));
        lexer.removeErrorListeners();
        CommonTokenStream tokens = new CommonTokenStream(lexer);
        CSharpParser parser = new CSharpParser(tokens);
        parser.removeErrorListeners();
        CSharpParser.Compilation_unitContext parseTree = parser.compilation_unit();

        CSharpTreeConverter converter = new CSharpTreeConverter();
        List<CSharpBlockTree> methodBodies = converter.extractMethodBodies(parseTree);

        Path moduleRoot = Paths.get(".").toAbsolutePath().normalize();
        SensorContextTester sensorContext = SensorContextTester.create(moduleRoot);

        InputFile inputFile =
                TestInputFileBuilder.create("test-module", filePath.toString())
                        .setContents(content)
                        .setCharset(StandardCharsets.UTF_8)
                        .setLanguage("cs")
                        .setType(InputFile.Type.MAIN)
                        .build();
        sensorContext.fileSystem().add(inputFile);

        CSharpScanContext scanContext =
                new CSharpScanContext(
                        sensorContext, inputFile, CSharpScannerRuleDefinition.REPOSITORY_KEY);

        for (CSharpBlockTree blockTree : methodBodies) {
            check.scan(scanContext, blockTree);
        }
    }
}
