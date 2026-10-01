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

import javax.annotation.Nonnull;

/**
 * Raises a SonarQube issue for a detached (tree-free) cross-file detection, at the given AST-free
 * location (e.g. Java's {@link DetachedSyntaxToken}, which fakes a {@code Tree}, or C++'s {@code
 * CxxDetachedAstNode}, which fakes an {@code AstNode}). Implemented per language over a shared,
 * non-AST-pinning reporting channel (for Java, {@code SonarComponents} + the file's {@code
 * InputFile}; for C++, the originating file's {@code SourceFile} data bag), so a detached record
 * can report an issue without retaining the file's AST.
 *
 * @param <R> the language's rule/check type
 * @param <T> the language's tree type; the location passed to {@link #report} is an AST-free
 *     stand-in for it
 */
@FunctionalInterface
public interface IDetachedIssueReporter<R, T> {

    void report(@Nonnull R rule, @Nonnull T location, @Nonnull String message);
}
