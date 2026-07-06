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
package com.ibm.engine.language.java;

import com.ibm.engine.callstack.DetachedSyntaxToken;
import com.ibm.engine.callstack.IDetachedIssueReporter;
import java.lang.reflect.Field;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.java.SonarComponents;
import org.sonar.java.model.DefaultModuleScannerContext;
import org.sonar.java.reporting.AnalyzerMessage;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;

/**
 * Raises a SonarQube issue for a detached (tree-free) cross-file detection through {@link
 * SonarComponents}, which is shared per scan and does not pin any file's AST. It is captured while
 * the file is live (at record time) together with the file's {@link InputFile}, so the issue can be
 * reported at the original call site later without keeping the file's {@code
 * JavaFileScannerContext}.
 *
 * <p>{@code SonarComponents} is an internal sonar-java type not exposed by the public {@code
 * JavaFileScannerContext} API, so it is read reflectively from {@link DefaultModuleScannerContext}
 * (extended by both the production context and the CheckVerifier test context). If it cannot be
 * obtained, {@link #create} returns {@code null} and issue reporting degrades to CBOM-only.
 */
public final class JavaDetachedIssueReporter implements IDetachedIssueReporter<JavaCheck> {

    private static final Logger LOGGER = LoggerFactory.getLogger(JavaDetachedIssueReporter.class);

    @Nonnull private final SonarComponents sonarComponents;
    @Nonnull private final InputFile inputFile;

    private JavaDetachedIssueReporter(
            @Nonnull SonarComponents sonarComponents, @Nonnull InputFile inputFile) {
        this.sonarComponents = sonarComponents;
        this.inputFile = inputFile;
    }

    @Nullable static JavaDetachedIssueReporter create(@Nonnull JavaFileScannerContext context) {
        final SonarComponents sonarComponents = extractSonarComponents(context);
        if (sonarComponents == null) {
            return null;
        }
        return new JavaDetachedIssueReporter(sonarComponents, context.getInputFile());
    }

    @Override
    public void report(
            @Nonnull JavaCheck rule,
            @Nonnull DetachedSyntaxToken location,
            @Nonnull String message) {
        final AnalyzerMessage.TextSpan span =
                new AnalyzerMessage.TextSpan(
                        location.line(),
                        location.offset(),
                        location.endLine(),
                        location.endOffset());
        sonarComponents.reportIssue(new AnalyzerMessage(rule, inputFile, span, message, 0));
    }

    @SuppressWarnings("java:S3011")
    @Nullable private static SonarComponents extractSonarComponents(@Nonnull JavaFileScannerContext context) {
        try {
            final Field field =
                    DefaultModuleScannerContext.class.getDeclaredField("sonarComponents");
            field.setAccessible(true);
            return (SonarComponents) field.get(context);
        } catch (ReflectiveOperationException | RuntimeException e) {
            LOGGER.debug("Detached issue reporting unavailable: {}", e.getMessage());
            return null;
        }
    }
}
