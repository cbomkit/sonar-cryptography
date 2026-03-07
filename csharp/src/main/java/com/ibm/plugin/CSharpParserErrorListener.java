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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.antlr.v4.runtime.BaseErrorListener;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.runtime.Recognizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.fs.InputFile;

/**
 * ANTLR error listener that logs parse errors at WARN level instead of silently discarding them.
 *
 * <p>Malformed C# files will still be partially scanned (the parser recovers where possible), but
 * any syntax errors encountered are surfaced as warnings so users know that analysis may be
 * incomplete for those files.
 */
public final class CSharpParserErrorListener extends BaseErrorListener {

    private static final Logger LOG = LoggerFactory.getLogger(CSharpParserErrorListener.class);

    @Nonnull private final InputFile inputFile;

    public CSharpParserErrorListener(@Nonnull InputFile inputFile) {
        this.inputFile = inputFile;
    }

    @Override
    public void syntaxError(
            @Nonnull Recognizer<?, ?> recognizer,
            @Nullable Object offendingSymbol,
            int line,
            int charPositionInLine,
            @Nonnull String msg,
            @Nullable RecognitionException e) {
        LOG.warn("Parse error in {}: line {}:{} — {}", inputFile, line, charPositionInLine, msg);
    }
}
