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

import java.util.ArrayList;
import java.util.List;
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

    /**
     * Collected messages rather than logged ones, because a file may be parsed twice: once with
     * every conditional branch active and, if that fails, once with a single branch (see {@code
     * CSharpConditionalDirectives}). Only the attempt that is actually used should report, so the
     * caller picks an attempt and calls {@link #flushToLog()} on it.
     */
    @Nonnull private final List<String> messages = new ArrayList<>();

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
        messages.add("line " + line + ":" + charPositionInLine + " — " + msg);
    }

    /** How many syntax errors this attempt produced. */
    public int errorCount() {
        return messages.size();
    }

    /** Logs the collected messages. Called only for the parse attempt that is kept. */
    public void flushToLog() {
        for (String message : messages) {
            LOG.warn("Parse error in {}: {}", inputFile, message);
        }
    }
}
