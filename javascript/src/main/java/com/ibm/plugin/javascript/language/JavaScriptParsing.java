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
package com.ibm.plugin.javascript.language;

import com.ibm.plugin.javascript.antlr.TypeScriptLexer;
import com.ibm.plugin.javascript.antlr.TypeScriptParser;
import javax.annotation.Nonnull;
import org.antlr.v4.runtime.BailErrorStrategy;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.DefaultErrorStrategy;
import org.antlr.v4.runtime.atn.PredictionMode;
import org.antlr.v4.runtime.misc.ParseCancellationException;

/**
 * The single entry point for parsing a JavaScript or TypeScript source file.
 *
 * <p>The grammar needs full ALL(*) lookahead for a small share of constructs, and running every
 * file that way is slow: on 40-130 KB files full LL took 2-6 s against 0.2-0.5 s in SLL mode. The
 * standard ANTLR remedy is applied: parse in SLL mode with a bail-out error strategy first, and
 * only when that bails out (SLL reports false syntax errors on some valid input) parse again with
 * full LL. The common case then costs one fast pass.
 */
public final class JavaScriptParsing {

    private JavaScriptParsing() {
        // utility
    }

    /** Result of parsing: the tree and the number of syntax errors the final pass reported. */
    public record Result(@Nonnull TypeScriptParser.ProgramContext tree, int syntaxErrors) {}

    @Nonnull
    public static Result parse(@Nonnull String source, @Nonnull String sourceName) {
        try {
            TypeScriptParser fast = newParser(source, sourceName);
            fast.getInterpreter().setPredictionMode(PredictionMode.SLL);
            fast.setErrorHandler(new BailErrorStrategy());
            fast.removeErrorListeners();
            TypeScriptParser.ProgramContext tree = fast.program();
            return new Result(tree, fast.getNumberOfSyntaxErrors());
        } catch (ParseCancellationException bailed) {
            TypeScriptParser full = newParser(source, sourceName);
            full.getInterpreter().setPredictionMode(PredictionMode.LL);
            full.setErrorHandler(new DefaultErrorStrategy());
            full.removeErrorListeners();
            TypeScriptParser.ProgramContext tree = full.program();
            return new Result(tree, full.getNumberOfSyntaxErrors());
        }
    }

    @Nonnull
    private static TypeScriptParser newParser(@Nonnull String source, @Nonnull String sourceName) {
        TypeScriptLexer lexer = new TypeScriptLexer(CharStreams.fromString(source, sourceName));
        lexer.removeErrorListeners();
        return new TypeScriptParser(new CommonTokenStream(lexer));
    }
}
