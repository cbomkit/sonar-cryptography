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
import org.sonar.cxx.config.CxxSquidConfiguration;
import org.sonar.cxx.squidbridge.SquidAstVisitor;

/**
 * Test verifier for C++ detection rules.
 *
 * <p>Scans a C++ test file using {@link CxxAstScanner} and invokes the provided check (typically a
 * {@link TestBase} instance) which intercepts detection findings and calls {@code asserts()}.
 *
 * <p>Fixtures use {@code #include <openssl/*.h>}. The OpenSSL headers path is auto-resolved in this
 * order:
 *
 * <ol>
 *   <li>{@code -Dopenssl.headers.dir=<path>} system property (set by Maven surefire from {@code
 *       cpp/pom.xml}; value defaults to {@code target/test-headers/openssl-<ver>/include} which the
 *       {@code download-maven-plugin} populates in the {@code generate-test-resources} phase).
 *   <li>{@code OPENSSL_HEADERS_DIR} environment variable.
 *   <li>Hard-coded fallback: {@code cpp/target/test-headers/openssl-3.6.2/include}.
 * </ol>
 *
 * <p>If no path resolves to an existing directory, the scanner still runs but the preprocessor will
 * emit "preprocessor cannot find include file" warnings and rules referencing symbols only visible
 * via headers (macros, typedefs) will fail to match.
 */
public final class CxxVerifier {

    private static final String TEST_FILES_BASE = "src/test/files/";
    private static final String INCLUDE_DIR_SYSTEM_PROPERTY = "openssl.headers.dir";
    private static final String INCLUDE_DIR_ENV_VAR = "OPENSSL_HEADERS_DIR";
    private static final String FALLBACK_INCLUDE_DIR =
            "cpp/target/test-headers/openssl-3.6.2/include";

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

            CxxSquidConfiguration squidConfig = new CxxSquidConfiguration();
            String includeDir = resolveIncludeDir();
            if (includeDir != null) {
                squidConfig.add(
                        CxxSquidConfiguration.GLOBAL,
                        CxxSquidConfiguration.INCLUDE_DIRECTORIES,
                        includeDir);
            }
            CxxAstScanner.scanSingleInputFileConfig(inputFile, squidConfig, check);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read test file: " + fullPath, e);
        }
    }

    /**
     * Resolves the OpenSSL headers directory from (in order): system property, env var, hard-coded
     * fallback. Returns null if no candidate resolves to an existing directory.
     */
    private static String resolveIncludeDir() {
        String fromSysProp = System.getProperty(INCLUDE_DIR_SYSTEM_PROPERTY);
        if (fromSysProp != null && !fromSysProp.isBlank() && new File(fromSysProp).isDirectory()) {
            return fromSysProp;
        }
        String fromEnv = System.getenv(INCLUDE_DIR_ENV_VAR);
        if (fromEnv != null && !fromEnv.isBlank() && new File(fromEnv).isDirectory()) {
            return fromEnv;
        }
        File fallback = new File(FALLBACK_INCLUDE_DIR);
        if (fallback.isDirectory()) {
            return fallback.getAbsolutePath();
        }
        return null;
    }
}
