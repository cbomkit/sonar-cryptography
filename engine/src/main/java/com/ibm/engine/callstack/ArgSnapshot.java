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

import java.util.List;
import javax.annotation.Nonnull;

/**
 * Tree-free snapshot of one argument of a detached recorded call: the value(s) it resolved to at
 * record time (while the file was still live) plus, for each, an AST-free location to report on.
 *
 * @param <T> the language's tree type, shared with the live (non-detached) path throughout the call
 *     stack ({@code DetachedCall<R, T>}, {@code IScanContext<R, T>}); the location is an AST-free
 *     stand-in for it (e.g. {@link DetachedSyntaxToken} for Java, which fakes a {@code Tree}) so it
 *     can flow through existing {@code T}-typed code unchanged. {@link
 *     DetachedScanContext#reportIssue} checks the actual runtime value against {@link
 *     DetachedLocation}.
 */
public record ArgSnapshot<T>(int index, @Nonnull List<ResolvedSnapshotValue<T>> values) {

    /** A single resolved value plus its detached location. */
    public record ResolvedSnapshotValue<T>(@Nonnull Object value, @Nonnull T location) {}
}
