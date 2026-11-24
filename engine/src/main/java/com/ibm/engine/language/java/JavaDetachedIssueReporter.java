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
import javax.annotation.Nonnull;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.plugins.java.api.JavaCheck;

/**
 * Reports an issue for a detached (tree-free) cross-file detection by queueing it in {@link
 * JavaDetachedIssueQueue}, together with the {@link InputFile} of the call site captured at record
 * time. The queue is flushed through the public sensor API once sonar-java has finished, so no
 * file's AST or {@code JavaFileScannerContext} is retained and no sonar-java internals are used.
 */
public record JavaDetachedIssueReporter(@Nonnull InputFile inputFile)
        implements IDetachedIssueReporter<JavaCheck> {

    @Override
    public void report(
            @Nonnull JavaCheck rule,
            @Nonnull DetachedSyntaxToken location,
            @Nonnull String message) {
        JavaDetachedIssueQueue.add(
                new JavaDetachedIssueQueue.Issue(rule, inputFile, location, message));
    }
}
