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
import org.sonar.api.batch.fs.InputFile;

/**
 * AST-free {@link IScanContext}: retains only the file handle and path captured at record time,
 * never the language-specific file scanner context (e.g. {@code JavaFileScannerContext}). A
 * detached recorded call carries this so that replaying it does not pin the file's AST.
 *
 * <p>{@link #reportIssue} is unavailable: cross-file detections are emitted to the CBOM via
 * translation, not via {@code reportIssue}, and the detached context has no live tree to report on.
 */
public record DetachedScanContext<R, T>(@Nonnull InputFile inputFile, @Nonnull String filePath)
        implements IScanContext<R, T> {

    @Override
    public void reportIssue(@Nonnull R currentRule, @Nonnull T tree, @Nonnull String message) {
        throw new UnsupportedOperationException(
                "reportIssue is not available on a detached scan context");
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
