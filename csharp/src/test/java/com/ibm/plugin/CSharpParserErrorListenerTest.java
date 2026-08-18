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

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.ibm.engine.language.csharp.antlr.CSharpLexer;
import com.ibm.engine.language.csharp.antlr.CSharpParser;
import java.nio.charset.StandardCharsets;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;

/**
 * Verifies that {@link CSharpParserErrorListener} emits a WARN log when the ANTLR parser encounters
 * a syntax error in a C# file.
 */
class CSharpParserErrorListenerTest {

    private Logger listenerLogger;
    private ListAppender<ILoggingEvent> listAppender;

    @BeforeEach
    void setUp() {
        listenerLogger = (Logger) LoggerFactory.getLogger(CSharpParserErrorListener.class);
        listAppender = new ListAppender<>();
        listAppender.start();
        listenerLogger.addAppender(listAppender);
    }

    @AfterEach
    void tearDown() {
        listenerLogger.detachAppender(listAppender);
    }

    @Test
    void warningIsLoggedForMalformedCSharp() {
        // Incomplete C# — missing closing braces triggers a parse error
        String brokenCode = "class Foo { void Bar() { Aes.Create();";

        InputFile inputFile =
                TestInputFileBuilder.create("test-module", "src/Broken.cs")
                        .setContents(brokenCode)
                        .setCharset(StandardCharsets.UTF_8)
                        .setLanguage("cs")
                        .setType(InputFile.Type.MAIN)
                        .build();

        CSharpLexer lexer =
                new CSharpLexer(CharStreams.fromString(brokenCode, inputFile.toString()));
        lexer.removeErrorListeners();
        lexer.addErrorListener(new CSharpParserErrorListener(inputFile));

        CommonTokenStream tokens = new CommonTokenStream(lexer);
        CSharpParser parser = new CSharpParser(tokens);
        parser.removeErrorListeners();
        parser.addErrorListener(new CSharpParserErrorListener(inputFile));

        parser.compilation_unit();

        assertThat(listAppender.list)
                .isNotEmpty()
                .anyMatch(
                        event ->
                                event.getLevel() == Level.WARN
                                        && event.getFormattedMessage().contains("Parse error"));
    }

    @Test
    void noWarningForValidCSharp() {
        String validCode =
                """
                class Foo {
                    void Bar() {
                        var aes = System.Security.Cryptography.Aes.Create();
                    }
                }
                """;

        InputFile inputFile =
                TestInputFileBuilder.create("test-module", "src/Valid.cs")
                        .setContents(validCode)
                        .setCharset(StandardCharsets.UTF_8)
                        .setLanguage("cs")
                        .setType(InputFile.Type.MAIN)
                        .build();

        CSharpLexer lexer =
                new CSharpLexer(CharStreams.fromString(validCode, inputFile.toString()));
        lexer.removeErrorListeners();
        lexer.addErrorListener(new CSharpParserErrorListener(inputFile));

        CommonTokenStream tokens = new CommonTokenStream(lexer);
        CSharpParser parser = new CSharpParser(tokens);
        parser.removeErrorListeners();
        parser.addErrorListener(new CSharpParserErrorListener(inputFile));

        parser.compilation_unit();

        assertThat(listAppender.list).noneMatch(event -> event.getLevel() == Level.WARN);
    }
}
