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
package com.ibm.engine.callstack;

import com.ibm.engine.language.IScanContext;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.fs.InputFile;

/**
 * AST-free {@link IScanContext}: retains only the file handle, path and a non-AST-pinning issue
 * reporter captured at record time, never the language-specific file scanner context (e.g. {@code
 * JavaFileScannerContext}, which holds the compilation unit). A detached recorded call carries this
 * so that replaying it does not pin the file's AST while still supporting CBOM translation and
 * cross-file SonarQube issue reporting.
 *
 * <p>{@link #reportIssue} raises the issue through {@link #issueReporter} when the location is a
 * {@link DetachedSyntaxToken}; if no reporter is available it logs and skips (the CBOM node is
 * still produced via translation).
 */
public record DetachedScanContext<R, T>(
        @Nonnull InputFile inputFile,
        @Nonnull String filePath,
        @Nullable IDetachedIssueReporter<R> issueReporter)
        implements IScanContext<R, T> {

    private static final Logger LOGGER = LoggerFactory.getLogger(DetachedScanContext.class);

    @Override
    public void reportIssue(@Nonnull R currentRule, @Nonnull T tree, @Nonnull String message) {
        if (issueReporter != null && tree instanceof DetachedSyntaxToken location) {
            issueReporter.report(currentRule, location, message);
            return;
        }
        LOGGER.debug(
                "Skipping issue on detached cross-file detection in {}: {}", filePath, message);
    }

    @Nonnull
    @Override
    public InputFile getInputFile() {
        return inputFile;
    }

    @Nonnull
    @Override
    public String getFilePath() {
        return filePath;
    }
}
