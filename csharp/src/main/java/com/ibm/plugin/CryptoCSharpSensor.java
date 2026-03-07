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
import java.util.Collection;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.fs.FileSystem;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.rule.CheckFactory;
import org.sonar.api.batch.sensor.Sensor;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.SensorDescriptor;

/**
 * Custom sensor for executing cryptography detection rules on C# source files.
 *
 * <p>Unlike Java/Python (which use SonarQube's {@code CheckRegistrar}) and Go (which reuses the
 * sonar-go {@code ChecksVisitor}), C# requires a fully custom sensor because sonar-csharp exposes
 * no public custom rule API. Each .cs file is parsed independently with the ANTLR4-based
 * CSharpLexer/CSharpParser, and detection checks are invoked directly for every method body found.
 */
public class CryptoCSharpSensor implements Sensor {

    private static final Logger LOG = LoggerFactory.getLogger(CryptoCSharpSensor.class);

    private final Collection<CSharpCheck> checks;

    public CryptoCSharpSensor(@Nonnull CheckFactory checkFactory) {
        this.checks =
                checkFactory
                        .<CSharpCheck>create(CSharpScannerRuleDefinition.REPOSITORY_KEY)
                        .addAnnotatedChecks(CSharpRuleList.getChecks())
                        .all();
    }

    @Override
    public void describe(@Nonnull SensorDescriptor descriptor) {
        descriptor.onlyOnLanguage("cs").name("Cryptography for C#");
    }

    @Override
    public void execute(@Nonnull SensorContext context) {
        if (checks.isEmpty()) {
            return;
        }

        FileSystem fs = context.fileSystem();
        Iterable<InputFile> csFiles =
                fs.inputFiles(
                        fs.predicates()
                                .and(
                                        fs.predicates().hasLanguage("cs"),
                                        fs.predicates().hasType(InputFile.Type.MAIN)));

        for (InputFile inputFile : csFiles) {
            if (context.isCancelled()) {
                return;
            }
            analyzeFile(context, inputFile);
        }
    }

    private void analyzeFile(@Nonnull SensorContext context, @Nonnull InputFile inputFile) {
        String content;
        try {
            content = inputFile.contents();
        } catch (IOException e) {
            LOG.warn("Unable to read file: {}", inputFile, e);
            return;
        }

        CSharpParser.Compilation_unitContext parseTree = parseContent(content, inputFile);
        if (parseTree == null) {
            return;
        }

        CSharpTreeConverter converter = new CSharpTreeConverter();
        List<CSharpBlockTree> methodBodies = converter.extractMethodBodies(parseTree);
        if (methodBodies.isEmpty()) {
            return;
        }

        CSharpScanContext scanContext =
                new CSharpScanContext(
                        context, inputFile, CSharpScannerRuleDefinition.REPOSITORY_KEY);

        for (CSharpBlockTree blockTree : methodBodies) {
            for (CSharpCheck check : checks) {
                try {
                    check.scan(scanContext, blockTree);
                } catch (RuntimeException e) {
                    LOG.warn(
                            "Error running check {} on {}: {}",
                            check.getClass().getSimpleName(),
                            inputFile,
                            e.getMessage(),
                            e);
                }
            }
        }
    }

    @Nullable private CSharpParser.Compilation_unitContext parseContent(
            @Nonnull String content, @Nonnull InputFile inputFile) {
        try {
            CSharpLexer lexer =
                    new CSharpLexer(CharStreams.fromString(content, inputFile.toString()));
            lexer.removeErrorListeners();
            lexer.addErrorListener(new CSharpParserErrorListener(inputFile));

            CommonTokenStream tokens = new CommonTokenStream(lexer);
            CSharpParser parser = new CSharpParser(tokens);
            parser.removeErrorListeners();
            parser.addErrorListener(new CSharpParserErrorListener(inputFile));

            return parser.compilation_unit();
        } catch (RuntimeException e) {
            LOG.warn("Unable to parse file: {}", inputFile, e);
            return null;
        }
    }
}
