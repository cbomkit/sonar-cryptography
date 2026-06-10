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

import com.sonar.cxx.sslr.api.Grammar;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import javax.annotation.Nonnull;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.cxx.CxxAstScanner;
import org.sonar.cxx.squidbridge.SquidAstVisitor;

/**
 * Test verifier for C++ detection rules.
 *
 * <p>Scans a C++ test file using {@link CxxAstScanner} and invokes the provided check (typically a
 * {@link TestBase} instance) which intercepts detection findings and calls {@code asserts()}.
 */
public final class CxxVerifier {

    private static final String TEST_FILES_BASE = "src/test/files/";

    private CxxVerifier() {
        // utility class
    }

    /**
     * Verifies a C++ test file by scanning it with the given check.
     *
     * @param relativePath Path to the test file relative to {@code src/test/files/}
     * @param check The check (detection rule) to apply
     */
    public static void verify(
            @Nonnull String relativePath, @Nonnull SquidAstVisitor<Grammar> check) {
        verify(relativePath, check, StandardCharsets.UTF_8);
    }

    /**
     * Verifies a C++ test file by scanning it with the given check and specified charset.
     *
     * @param relativePath Path to the test file relative to {@code src/test/files/}
     * @param check The check (detection rule) to apply
     * @param charset The character set of the test file
     */
    public static void verify(
            @Nonnull String relativePath,
            @Nonnull SquidAstVisitor<Grammar> check,
            @Nonnull Charset charset) {
        String fullPath = TEST_FILES_BASE + relativePath;
        File file = new File(fullPath);
        if (!file.isFile()) {
            throw new IllegalArgumentException("Test file not found: " + file.getAbsolutePath());
        }

        try {
            String content = new String(java.nio.file.Files.readAllBytes(file.toPath()), charset);
            InputFile inputFile =
                    TestInputFileBuilder.create("", fullPath)
                            .setCharset(charset)
                            .setProjectBaseDir(Path.of("."))
                            .setContents(content)
                            .build();
            CxxAstScanner.scanSingleInputFile(inputFile, check);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read test file: " + fullPath, e);
        }
    }
}
