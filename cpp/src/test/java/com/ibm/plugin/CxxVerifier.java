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
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.cxx.CxxAstScanner;
import org.sonar.cxx.config.CxxSquidConfiguration;
import org.sonar.cxx.squidbridge.AstScanner;
import org.sonar.cxx.squidbridge.SquidAstVisitor;

/**
 * Test verifier for C++ detection rules.
 *
 * <p>Scans a C++ test file using {@link CxxAstScanner} and invokes the provided check (typically a
 * {@link TestBase} instance) which intercepts detection findings and calls {@code asserts()}.
 *
 * <p>No include directories are configured. Detection matches the literal OpenSSL API calls, so it
 * does not depend on the preprocessor expanding headers. The preprocessor may log "cannot find
 * include file" at DEBUG for the fixtures' {@code #include} lines; that is harmless.
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
    @SuppressWarnings("unchecked") // CxxAstScanner.scanSingleInputFileConfig takes
    // SquidAstVisitor<Grammar>... varargs — passing a single typed visitor
    // triggers a harmless generic-array creation warning
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

            // No include directories are configured: detection matches the literal OpenSSL API
            // calls, so it does not depend on the preprocessor expanding headers. The preprocessor
            // may log "cannot find include file" at DEBUG for the fixtures' #include lines; that is
            // harmless and does not affect detection.
            CxxSquidConfiguration squidConfig = new CxxSquidConfiguration();
            CxxAstScanner.scanSingleInputFileConfig(inputFile, squidConfig, check);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read test file: " + fullPath, e);
        }
    }

    /**
     * Verifies multiple C++ test files in a single scan, sharing one {@link AstScanner} (and thus
     * one {@code SquidAstVisitorContext}) across all of them — the same shape as a real multi-file
     * SonarQube analysis. Files are scanned in the given order; {@code leaveFile} fires once per
     * file as each finishes, before the next one starts, matching production behavior. Unlike
     * {@link #verify}, this does not assert a single {@code SourceFile} was produced.
     *
     * @param relativePaths Paths to the test files relative to {@code src/test/files/}, in scan
     *     order
     * @param check The check (detection rule) to apply across all files
     */
    public static void verifyFiles(
            @Nonnull List<String> relativePaths, @Nonnull SquidAstVisitor<Grammar> check) {
        verifyFiles(relativePaths, check, StandardCharsets.UTF_8);
    }

    /**
     * Verifies multiple C++ test files in a single scan, sharing one {@link AstScanner} (and thus
     * one {@code SquidAstVisitorContext}) across all of them — the same shape as a real multi-file
     * SonarQube analysis. Files are scanned in the given order; {@code leaveFile} fires once per
     * file as each finishes, before the next one starts, matching production behavior. Unlike
     * {@link #verify}, this does not assert a single {@code SourceFile} was produced.
     *
     * @param relativePaths Paths to the test files relative to {@code src/test/files/}, in scan
     *     order
     * @param check The check (detection rule) to apply across all files
     * @param charset The character set of the test files
     */
    @SuppressWarnings("unchecked") // CxxAstScanner.create takes SquidAstVisitor<Grammar>...
    // varargs — passing a single typed visitor triggers a harmless generic-array creation warning
    public static void verifyFiles(
            @Nonnull List<String> relativePaths,
            @Nonnull SquidAstVisitor<Grammar> check,
            @Nonnull Charset charset) {
        List<InputFile> inputFiles = new ArrayList<>(relativePaths.size());
        for (String relativePath : relativePaths) {
            String fullPath = TEST_FILES_BASE + relativePath;
            File file = new File(fullPath);
            if (!file.isFile()) {
                throw new IllegalArgumentException(
                        "Test file not found: " + file.getAbsolutePath());
            }
            try {
                String content =
                        new String(java.nio.file.Files.readAllBytes(file.toPath()), charset);
                inputFiles.add(
                        TestInputFileBuilder.create("", fullPath)
                                .setCharset(charset)
                                .setProjectBaseDir(Path.of("."))
                                .setContents(content)
                                .build());
            } catch (IOException e) {
                throw new IllegalStateException("Failed to read test file: " + fullPath, e);
            }
        }

        // No include directories are configured: detection matches the literal OpenSSL API calls,
        // so it does not depend on the preprocessor expanding headers.
        CxxSquidConfiguration squidConfig = new CxxSquidConfiguration();
        AstScanner<Grammar> scanner = CxxAstScanner.create(squidConfig, check);
        scanner.scanInputFiles(inputFiles);
    }
}
